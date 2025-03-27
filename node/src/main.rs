#![feature(trivial_bounds)]
use base64::Engine;
use clap::{Parser, Subcommand};
use libp2p::PeerId;
use libp2p::bytes::BufMut;
use libp2p::futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::{
    gossipsub, kad, mdns,
    multiaddr::{Multiaddr, Protocol},
    noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use libp2p_metrics::{Metrics, Registry};
use std::io::{Read, Write};
use std::ops::Add;
use std::str::FromStr;
use std::thread::LocalKey;
use std::{
    error::Error,
    net::Ipv4Addr,
    time::{Duration, Instant},
};
use tokio::{io, io::AsyncBufReadExt, select};

use opentelemetry::{KeyValue, trace::TracerProvider as _};
use opentelemetry_sdk::{runtime, trace::TracerProvider};
use tracing::log::__private_api::loc;
use tracing_subscriber::{EnvFilter, Layer, layer::SubscriberExt, util::SubscriberInitExt};

use zeroize::Zeroizing;

use bitvm2_lib::actors::Actor;
use identity;

mod action;
mod metrics_service;
mod middleware;
mod rpc_service;

pub use middleware::authenticator;

use crate::middleware::behaviour::AllBehavioursEvent;
use anyhow::{Result, bail};
use middleware::AllBehaviours;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Opts {
    #[arg(short)]
    daemon: bool,

    #[arg(long, default_value = "0.0.0.0:8080")]
    pub rpc_addr: String,

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
                    println!("export KEY={}", base64_key);
                    println!("export PEER_ID={}", local_key.public().to_peer_id());
                }
            }
            return Ok(());
        }
        _ => {}
    }
    // load role
    let actor =
        Actor::try_from(std::env::var("ACTOR").unwrap_or("Challenger".to_string()).as_str())
            .unwrap();

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

    // Add the bootnodes to the local routing table. `libp2p-dns` built
    // into the `transport` resolves the `dnsaddr` when Kademlia tries
    // to dial these nodes.
    println!("bootnodes: {:?}", opt.bootnodes);
    for peer in &opt.bootnodes {
        swarm
            .behaviour_mut()
            .kademlia
            .add_address(&peer.parse()?, "/dnsaddr/bootstrap.libp2p.io".parse()?);
    }

    // Create a Gosspipsub topic
    let gossipsub_topic = gossipsub::IdentTopic::new("chat");
    println!("Subscribing to {gossipsub_topic:?}");
    swarm.behaviour_mut().gossipsub.subscribe(&gossipsub_topic).unwrap();

    match &opt.cmd {
        Some(Commands::Peer(key_arg)) => match &key_arg.peer_cmd {
            PeerCommands::GetPeers { peer_id } => {
                let peer_id = peer_id.unwrap_or(PeerId::random());
                println!("Searching for the closest peers to {peer_id}");
                swarm.behaviour_mut().kademlia.get_closest_peers(peer_id);
                //return Ok(());
            }
        },
        _ => {
            //if !opt.daemon {
            //    println!("Help");
            //    return Ok(());
            //}
        }
    }

    // Tell the swarm to listen on all interfaces and a random, OS-assigned
    // port.
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
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

    println!("RPC service listening on {}", &opt.rpc_addr);
    let rpc_addr = opt.rpc_addr.clone();
    tokio::spawn(rpc_service::serve(rpc_addr));

    // Read full lines from stdin
    let mut stdin = io::BufReader::new(io::stdin()).lines();
    loop {
        select! {
                Ok(Some(line)) = stdin.next_line() => {
                    if let Err(e) = swarm
                        .behaviour_mut()
                        .gossipsub
                        .publish(gossipsub_topic.clone(), line.as_bytes())
                    {
                        println!("Publish error: {e:?}");
                    }
                },
                event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {address:?}"),
                    SwarmEvent::Behaviour(AllBehavioursEvent::Gossipsub(gossipsub::Event::Message {
                                                                  propagation_source: peer_id,
                                                                  message_id: id,
                                                                  message,
                                                              })) => {
                        action::recv_and_dispatch(&mut swarm, peer_id, id, &message.data)?
                    }
                    SwarmEvent::Behaviour(AllBehavioursEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic})) => {
                        println!("subscribed: {:?}, {:?}", peer_id, topic);
                    }
                    SwarmEvent::Behaviour(AllBehavioursEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer_id, multiaddr) in list {
                            println!("add peer: {:?}: {:?}", peer_id, multiaddr);
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr);
                        }
                    }

                    SwarmEvent::Behaviour(AllBehavioursEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                        result: kad::QueryResult::GetClosestPeers(Ok(ok)),
                        ..
                    })) => {
                        // The example is considered failed as there
                        // should always be at least 1 reachable peer.
                        if ok.peers.is_empty() {
                            println!("Query finished with no closest peers.");
                        }

                        println!("Query finished with closest peers: {:#?}", ok.peers);

                        //return Ok(());
                    }

                    e => {
                        println!("Unhandled {:?}", e);
                    }
                }
            }
        }
    }
}
