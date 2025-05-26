#![feature(trivial_bounds)]
use base64::Engine;
use bitvm2_noded::client::{BTCClient, GOATClient};
use clap::{Parser, Subcommand, command};
use libp2p::futures::StreamExt;
use libp2p::{Multiaddr, PeerId};
use libp2p::{gossipsub, kad, multiaddr::Protocol, noise, swarm::SwarmEvent, tcp, yamux};
use libp2p_metrics::Registry;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::{error::Error, net::Ipv4Addr, time::Duration};
use store::ipfs::IPFS;
use tokio::{io, io::AsyncBufReadExt, select};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

use bitvm2_lib::actors::Actor;

use bitvm2_noded::action::{self, GOATMessage, GOATMessageContent, send_to_peer};
use bitvm2_noded::env::{
    self, ENV_PEER_KEY, check_node_info, get_ipfs_url, get_local_node_info, get_network,
    get_node_pubkey,
};
use bitvm2_noded::middleware::{
    self, AllBehaviours, behaviour::AllBehavioursEvent, split_topic_name,
};
use bitvm2_noded::rpc_service;
use bitvm2_noded::utils::{self, detect_heart_beat, save_local_info};

use anyhow::Result;
use bitvm2_noded::relayer_action::monitor_events;
use tokio::time::interval;

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

fn parse_boot_node_str(boot_node_str: &str) -> Result<(PeerId, Multiaddr), String> {
    let multi_addr: Multiaddr =
        boot_node_str.parse().map_err(|e| format!("boot_node_str parse to multi addr err :{e}"))?;
    println!("multi_addr: {multi_addr}");
    for protocol in multi_addr.iter() {
        if let Protocol::P2p(peer_id) = protocol {
            return Ok((peer_id, multi_addr));
        }
    }
    Err("parse bootnode failed".to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv::dotenv().ok();
    let actor = env::get_actor();
    let opt = Opts::parse();
    if let Some(Commands::Key(key_arg)) = opt.cmd {
        match key_arg.cmd {
            KeyCommands::Peer => {
                let local_key = identity::generate_local_key();
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
    // load role
    let local_key = env::get_peer_key();

    let _ = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).try_init();
    let mut metric_registry = Registry::default();

    let local_key = libp2p::identity::Keypair::from_protobuf_encoding(&Zeroizing::new(
        base64::engine::general_purpose::STANDARD.decode(local_key)?,
    ))?;

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_bandwidth_metrics(&mut metric_registry)
        .with_behaviour(AllBehaviours::new)?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX)))
        .build();

    // Add the bootnodes to the local routing table. `libp2p-dns` built
    // into the `transport` resolves the `dnsaddr` when Kademlia tries
    // to dial these nodes.
    tracing::debug!("bootnodes: {:?}", opt.bootnodes);
    for peer in &opt.bootnodes {
        let (peer_id, multi_addr) = parse_boot_node_str(peer)?;
        swarm.behaviour_mut().kademlia.add_address(&peer_id, multi_addr);
    }

    // Create a Gosspipsub topic, we create 3 topics: committee, challenger, and operator
    let topics = [Actor::Committee, Actor::Challenger, Actor::Operator, Actor::Relayer, Actor::All]
        .iter()
        .map(|a| {
            let topic_name = middleware::get_topic_name(&a.to_string());
            let gossipsub_topic = gossipsub::IdentTopic::new(topic_name.clone());
            swarm.behaviour_mut().gossipsub.subscribe(&gossipsub_topic).unwrap();
            (topic_name, gossipsub_topic)
        })
        .collect::<HashMap<String, _>>();

    if let Some(Commands::Peer(key_arg)) = &opt.cmd {
        match &key_arg.peer_cmd {
            PeerCommands::GetPeers { peer_id } => {
                let peer_id = peer_id.unwrap_or(PeerId::random());
                tracing::debug!("Searching for the closest peers to {peer_id}");
                swarm.behaviour_mut().kademlia.get_closest_peers(peer_id);
                //return Ok(());
            }
        }
    }

    // Tell the swarm to listen on all interfaces and a random, OS-assigned
    // port.
    if opt.p2p_port > 0 {
        swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", opt.p2p_port).parse()?)?;
    } else {
        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    }

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

    tracing::info!(
        "multi_addr: {}/p2p/{}",
        address.to_string(),
        local_key.public().to_peer_id().to_string()
    );

    tracing::debug!("RPC service listening on {}", &opt.rpc_addr);
    let rpc_addr = opt.rpc_addr.clone();
    let db_path = opt.db_path.clone();
    let ipfs_url = get_ipfs_url();

    let local_db = bitvm2_noded::client::create_local_db(&db_path).await;
    let btc_client = BTCClient::new(None, env::get_network());
    let goat_client = GOATClient::new(env::goat_config_from_env().await, env::get_goat_network());
    let ipfs = IPFS::new(&ipfs_url);

    // validate node info
    check_node_info().await;
    save_local_info(&local_db).await;

    tokio::spawn(rpc_service::serve(
        rpc_addr,
        db_path.clone(),
        actor.clone(),
        local_key.public().to_peer_id().to_string(),
        Arc::new(Mutex::new(metric_registry)),
    ));
    // Read full lines from stdin
    let mut heart_beat_interval = interval(Duration::from_secs(300));
    let mut l2_watch_interval = interval(Duration::from_secs(5));
    let mut interval = interval(Duration::from_secs(20));
    let mut stdin = io::BufReader::new(io::stdin()).lines();
    loop {
        select! {
                // For testing only
                Ok(Some(line)) = stdin.next_line() => {
                    let commands = match line.split_once(":") {
                        Some((actor,msg)) => (actor.trim(),msg),
                        _ => {
                            println!("Message format: actor:message");
                        continue
                        }
                    };

                    let topic_str = crate::middleware::get_topic_name(commands.0);
                    if let Some(gossipsub_topic) = topics.get(&topic_str) {
                        let message = serde_json::to_vec(&GOATMessage{
                            actor: Actor::from_str(commands.0).unwrap(),
                            content: commands.1.as_bytes().to_vec(),
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
                _ticker = interval.tick() => {
                    // using a ticker to activate the handler of the asynchronous message in local database
                    let peer_id = local_key.public().to_peer_id();
                    let tick_data = serde_json::to_vec(&GOATMessage{
                        actor: actor.clone(),
                        content: "tick".as_bytes().to_vec(),
                    })?;
                    match action::recv_and_dispatch(&mut swarm, &local_db, &btc_client, &goat_client, &ipfs, actor.clone(), peer_id, GOATMessage::default_message_id(), &tick_data).await{
                        Ok(_) => {}
                        Err(e) => { tracing::error!(e) }
                    }
                },

               _ticker = l2_watch_interval.tick() => {
                    match monitor_events(&goat_client,&local_db).await{
                        Ok(_) => {}
                        Err(e) => { tracing::error!(e) }
                    }
                },

                _ticker = heart_beat_interval.tick() =>{
                    match detect_heart_beat(&mut swarm).await{
                        Ok(_) => {}
                        Err(e) => { tracing::error!(e) }
                    }
                },
                event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => tracing::debug!("Listening on {address:?}"),
                    SwarmEvent::Behaviour(AllBehavioursEvent::Gossipsub(gossipsub::Event::Message {
                                                                  propagation_source: _peer_id,
                                                                  message_id: id,
                                                                  message,
                                                              })) => {
                        match action::recv_and_dispatch(&mut swarm, &local_db, &btc_client, &goat_client, &ipfs, actor.clone(),
                            message.source.expect("empty message source"), id, &message.data).await {
                            Ok(_) => {},
                            Err(e) => { tracing::error!(e) }
                        }
                    }
                    SwarmEvent::Behaviour(AllBehavioursEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic})) => {
                        tracing::debug!("subscribing: {:?}, {:?}", peer_id, topic);
                        let topic_limb = split_topic_name(topic.as_str());//topic.as_str().split_once("/topic/").expect("should be $proto/topic/$actor");
                        if topic_limb.0 != env::get_proto_base() {
                           continue;
                        }
                        let topic = topic_limb.1;
                        tracing::debug!("subscribed: {:?}, {:?}", peer_id, topic);
                        // Except for the bootNode, all other nodes need to request information from other nodes after registering the event `ALL`.
                        if topic == Actor::All.to_string() && opt.bootnodes.is_empty() {
                            let message_content = GOATMessageContent::RequestNodeInfo(get_local_node_info());
                            send_to_peer(&mut swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
                        }

                    }
                    SwarmEvent::Behaviour(AllBehavioursEvent::Gossipsub(gossipsub::Event::Unsubscribed { peer_id, topic})) => {
                        tracing::debug!("unsubscribed: {:?}, {:?}", peer_id, topic);
                    }
                    SwarmEvent::Behaviour(AllBehavioursEvent::Kademlia(kad::Event::RoutingUpdated{ peer, addresses,..})) => {
                        tracing::debug!("routing updated: {:?}, addresses:{:?}", peer, addresses);
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
                    SwarmEvent::ConnectionEstablished {peer_id, connection_id, endpoint, .. } => {
                        tracing::debug!("connected to {peer_id}: {connection_id}, endpoint: {:?}", endpoint);
                    }
                    e => {
                        tracing::debug!("Unhandled {:?}", e);
                    }
                }
            }
        }
    }
}
