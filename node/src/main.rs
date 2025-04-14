#![feature(trivial_bounds)]
use base64::Engine;
use clap::{Parser, Subcommand, command};
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
use std::collections::HashMap;
use std::io::{Read, Write};
use std::ops::Add;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
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
mod bitcoin;
mod metrics_service;
mod middleware;
mod rpc_service;

use crate::action::GOATMessage;
use crate::middleware::behaviour::AllBehavioursEvent;
use anyhow::{Result, bail};
use libp2p::gossipsub::{MessageId, Topic};
use middleware::AllBehaviours;
use tokio::time::interval;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Opts {
    #[arg(short)]
    daemon: bool,

    #[arg(long, default_value = "0.0.0.0:8080")]
    pub rpc_addr: String,

    #[arg(long, default_value = "/tmp/bitvm2-node.db")]
    pub db_path: String,

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
                    tracing::info!("export KEY={}", base64_key);
                    tracing::info!("export PEER_ID={}", local_key.public().to_peer_id());
                }
            }
            return Ok(());
        }
        _ => {}
    }
    // load role
    let actor =
        Actor::from_str(std::env::var("ACTOR").unwrap_or("Challenger".to_string()).as_str())
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
    tracing::debug!("bootnodes: {:?}", opt.bootnodes);
    for peer in &opt.bootnodes {
        swarm
            .behaviour_mut()
            .kademlia
            .add_address(&peer.parse()?, "/dnsaddr/bootstrap.libp2p.io".parse()?);
    }

    // Create a Gosspipsub topic, we create 3 topics: committee, challenger, and operator
    let topics = [Actor::Committee, Actor::Challenger, Actor::Operator]
        .iter()
        .map(|a| {
            let topic_name = a.to_string();
            let gossipsub_topic = gossipsub::IdentTopic::new(topic_name.clone());
            swarm.behaviour_mut().gossipsub.subscribe(&gossipsub_topic).unwrap();
            (topic_name, gossipsub_topic)
        })
        .collect::<HashMap<String, _>>();

    match &opt.cmd {
        Some(Commands::Peer(key_arg)) => match &key_arg.peer_cmd {
            PeerCommands::GetPeers { peer_id } => {
                let peer_id = peer_id.unwrap_or(PeerId::random());
                tracing::debug!("Searching for the closest peers to {peer_id}");
                swarm.behaviour_mut().kademlia.get_closest_peers(peer_id);
                //return Ok(());
            }
        },
        _ => {
            //if !opt.daemon {
            //    tracing::debug!("Help");
            //    return Ok(());
            //}
        }
    }

    // Tell the swarm to listen on all interfaces and a random, OS-assigned
    // port.
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

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

    tracing::debug!("RPC service listening on {}", &opt.rpc_addr);
    let rpc_addr = opt.rpc_addr.clone();
    let db_path = opt.db_path.clone();

    tokio::spawn(rpc_service::serve(rpc_addr, db_path, Arc::new(Mutex::new(metric_registry))));
    // Read full lines from stdin
    let mut interval = interval(Duration::from_secs(20));
    let mut stdin = io::BufReader::new(io::stdin()).lines();
    loop {
        select! {
                // For testing only
                Ok(Some(line)) = stdin.next_line() => {
                    let commands = line.split(":").collect::<Vec<_>>();
                    if commands.len() < 2 || commands[0].trim().is_empty() {
                        println!("Message format: actor:message");
                        continue
                    }

                    if let Some(gossipsub_topic) = topics.get(commands[0]) {
                        let message = serde_json::to_vec(&GOATMessage{
                            actor: Actor::from_str(&commands[0]).unwrap(),
                            content: commands[1].as_bytes().to_vec(),
                        }).unwrap();
                        if let Err(e) = swarm
                            .behaviour_mut()
                            .gossipsub
                            .publish(gossipsub_topic.clone(), message)
                        {
                            tracing::debug!("Publish error: {e:?}");
                        }
                    }
                },
                ticker = interval.tick() => {
                    // using a ticker to activate the handler of the asynchronous message in local database
                    let peer_id = local_key.public().to_peer_id();
                    let tick_data = serde_json::to_vec(&GOATMessage{
                        actor: actor.clone(),
                        content: "tick".as_bytes().to_vec(),
                    })?;
                    match action::recv_and_dispatch(&mut swarm, actor.clone(), peer_id, GOATMessage::default_message_id(), &tick_data){
                        Ok(_) => {}
                        Err(e) => { tracing::error!(e) }
                    }
                },
                event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => tracing::debug!("Listening on {address:?}"),
                    SwarmEvent::Behaviour(AllBehavioursEvent::Gossipsub(gossipsub::Event::Message {
                                                                  propagation_source: peer_id,
                                                                  message_id: id,
                                                                  message,
                                                              })) => {
                        match action::recv_and_dispatch(&mut swarm, actor.clone(), peer_id, id, &message.data) {
                            Ok(_) => {},
                            Err(e) => { tracing::error!(e) }
                        }
                    }
                    SwarmEvent::Behaviour(AllBehavioursEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic})) => {
                        tracing::debug!("subscribed: {:?}, {:?}", peer_id, topic);
                    }
                    SwarmEvent::Behaviour(AllBehavioursEvent::Gossipsub(gossipsub::Event::Unsubscribed { peer_id, topic})) => {
                        tracing::debug!("unsubscribed: {:?}, {:?}", peer_id, topic);
                    }
                    SwarmEvent::Behaviour(AllBehavioursEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer_id, multiaddr) in list {
                            tracing::debug!("add peer: {:?}: {:?}", peer_id, multiaddr);
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr);
                        }
                    }
                    SwarmEvent::Behaviour(AllBehavioursEvent::Kademlia(kad::Event::RoutingUpdated{ peer, addresses,..})) => {
                        tracing::debug!("routing updated: {:?}", peer);
                    }
                    SwarmEvent::Behaviour(AllBehavioursEvent::Mdns(mdns::Event::Expired(list))) => {
                        tracing::debug!("expired: {:?}", list);
                    }

                    SwarmEvent::Behaviour(AllBehavioursEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                        result: kad::QueryResult::GetClosestPeers(Ok(ok)),
                        ..
                    })) => {
                        // The example is considered failed as there
                        // should always be at least 1 reachable peer.
                        if ok.peers.is_empty() {
                            tracing::debug!("Query finished with no closest peers.");
                        }

                        tracing::debug!("Query finished with closest peers: {:#?}", ok.peers);
                        //return Ok(());
                    }
                    SwarmEvent::Behaviour(AllBehavioursEvent::Kademlia(kad::Event::InboundRequest {request})) => {
                        tracing::debug!("kademlia: {:?}", request);
                    }
                    SwarmEvent::NewExternalAddrOfPeer {peer_id, address} => {
                        tracing::debug!("new external address of peer: {} {}", peer_id, address);
                    }
                    SwarmEvent::ConnectionEstablished {peer_id, connection_id,endpoint, .. } => {
                        tracing::debug!("connected to {peer_id}: {connection_id}");
                    }
                    e => {
                        tracing::debug!("Unhandled {:?}", e);
                    }
                }
            }
        }
    }
}
