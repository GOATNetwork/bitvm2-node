use base64::Engine;
use clap::{Parser, Subcommand};
use libp2p::bytes::BufMut;
use libp2p::PeerId;
use libp2p::futures::StreamExt;
use libp2p::identity::Keypair;
use std::ops::Add;
use libp2p::{
    kad, mdns,
    multiaddr::{Multiaddr, Protocol},
    noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use libp2p_metrics::{Metrics, Registry};
use std::io::{Read, Write};
use std::str::FromStr;
use std::thread::LocalKey;
use std::{error::Error, net::Ipv4Addr, time::{Duration, Instant}};

use opentelemetry::{KeyValue, trace::TracerProvider as _};
use opentelemetry_otlp::SpanExporter;
use opentelemetry_sdk::{runtime, trace::TracerProvider};
use tracing::log::__private_api::loc;
use tracing_subscriber::{EnvFilter, Layer, layer::SubscriberExt, util::SubscriberInitExt};

use zeroize::Zeroizing;

use bitvm2_lib::actors::Actor;
use identity;

mod metrics_service;
mod middleware;
mod rpc_service;
mod action;

pub use middleware::authenticator;

use crate::middleware::behaviour::AllBehavioursEvent;
use middleware::AllBehaviours;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Opts {
    #[arg(short)]
    daemon: bool,

    #[arg(long)]
    bootnodes: Vec<String>,

    // #[arg(long)]
    // local_peer_id: Option<String>,

    // #[arg(long)]
    // local_key: Option<String>,

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
    cmd: Option<Commands>,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    Key(KeyArg),
    Peer(PeerArg)
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
    PutPkRecord {},
}

#[derive(Subcommand, Debug, Clone)]
enum KeyCommands {
    Gen,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let opt = Opts::parse();
    match opt.cmd {
        Some(Commands::Key(key_arg)) => {
            match key_arg.cmd {
                KeyCommands::Gen => {
                    let local_key = identity::generate_local_key();
                    let base64_key = base64::engine::general_purpose::STANDARD
                        .encode(&local_key.to_protobuf_encoding()?);
                    println!("key: {}", base64_key);
                    println!("peer_id: {}", local_key.public().to_peer_id());
                }
            }
            return Ok(());
        },
        _ => {
            if !opt.daemon {
                // TODO
                println!("Help");
                return Ok(());
            }
        }
    }
    // load role
    let actor =
        Actor::try_from(
            std::env::var("ACTOR").unwrap_or("Challenger".to_string()).as_str()
        ).unwrap();

    let local_key = std::env::var("KEY").expect("KEY is missing");
    let arg_peer_id = std::env::var("PEER_ID").expect("Peer ID is missing");

    let _ = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).try_init();

    let mut metric_registry = Registry::default();

    let local_key = {
        let keypair = libp2p::identity::Keypair::from_protobuf_encoding(&Zeroizing::new(
            base64::engine::general_purpose::STANDARD.decode(local_key)?,
        ))?;

        let peer_id = keypair.public().into();
        assert_eq!(
            PeerId::from_str(&arg_peer_id)?,
            peer_id,
            "Expect peer id derived from private key and peer id retrieved from config to match."
        );

        keypair
    };
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_bandwidth_metrics(&mut metric_registry)
        .with_behaviour(|key| AllBehaviours::new(key))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX)))
        .build();
    // Tell the swarm to listen on all interfaces and a random, OS-assigned
    // port.
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    //let metrics = Metrics::new(&mut metric_registry);
    tokio::spawn(metrics_service::metrics_server(metric_registry));

    // run a http server for front-end
    let address = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            if address.iter().any(|e| e == Protocol::Ip4(Ipv4Addr::LOCALHOST)) {
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
    println!("RPC service listening on {}", addr);
    tokio::spawn(rpc_service::serve(addr));

    // Add the bootnodes to the local routing table. `libp2p-dns` built
    // into the `transport` resolves the `dnsaddr` when Kademlia tries
    // to dial these nodes.
    for peer in &opt.bootnodes {
        swarm
            .behaviour_mut().kademlia
            .add_address(&peer.parse()?, "/dnsaddr/bootstrap.libp2p.io".parse()?);
    }


    match opt.cmd {
        Some(Commands::Peer(key_arg)) => match key_arg.peer_cmd {
            PeerCommands::GetPeers { peer_id } => {
                let peer_id = peer_id.unwrap_or(PeerId::random());
                println!("Searching for the closest peers to {peer_id}");
                swarm.behaviour_mut().kademlia.get_closest_peers(peer_id);
            }
            PeerCommands::PutPkRecord {} => {
                println!("Putting PK record into the DHT");

                let mut pk_record_key = vec![];
                pk_record_key.put_slice("/pk/".as_bytes());
                pk_record_key.put_slice(swarm.local_peer_id().to_bytes().as_slice());

                let mut pk_record =
                    kad::Record::new(pk_record_key, local_key.public().encode_protobuf());
                pk_record.publisher = Some(*swarm.local_peer_id());
                pk_record.expires = Some(Instant::now().add(Duration::from_secs(60)));

                swarm
                    .behaviour_mut()
                    .kademlia
                    .put_record(pk_record, kad::Quorum::N(std::num::NonZeroUsize::new(3).unwrap()))?;
            }
        },
        _ =>  {}
    }

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {address:?}"),
            SwarmEvent::Behaviour(AllBehavioursEvent::Mdns(mdns::Event::Discovered(list))) => {
                for (peer_id, multiaddr) in list {
                    swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr);
                }
            }
            SwarmEvent::Behaviour(AllBehavioursEvent::Kademlia(
                kad::Event::OutboundQueryProgressed { result, .. },
            )) => match result {
                kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders {
                    key,
                    providers,
                    ..
                })) => {
                    for peer in providers {
                        println!(
                            "Peer {peer:?} provides key {:?}",
                            std::str::from_utf8(key.as_ref()).unwrap()
                        );
                    }
                }
                kad::QueryResult::GetProviders(Err(err)) => {
                    eprintln!("Failed to get providers: {err:?}");
                }
                kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(
                    kad::PeerRecord { record: kad::Record { key, value, .. }, .. },
                ))) => {
                    println!(
                        "Got record {:?} {:?}",
                        std::str::from_utf8(key.as_ref()).unwrap(),
                        std::str::from_utf8(&value).unwrap(),
                    );
                }
                kad::QueryResult::GetRecord(Ok(_)) => {}
                kad::QueryResult::GetRecord(Err(err)) => {
                    eprintln!("Failed to get record: {err:?}");
                }
                kad::QueryResult::PutRecord(Ok(kad::PutRecordOk { key })) => {
                    println!(
                        "Successfully put record {:?}",
                        std::str::from_utf8(key.as_ref()).unwrap()
                    );
                }
                kad::QueryResult::PutRecord(Err(err)) => {
                    eprintln!("Failed to put record: {err:?}");
                }
                kad::QueryResult::StartProviding(Ok(kad::AddProviderOk { key })) => {
                    println!(
                        "Successfully put provider record {:?}",
                        std::str::from_utf8(key.as_ref()).unwrap()
                    );
                }
                kad::QueryResult::StartProviding(Err(err)) => {
                    eprintln!("Failed to put provider record: {err:?}");
                }
                _ => {}
            },
            _ => {}
        }
    }
    Ok(())
}
