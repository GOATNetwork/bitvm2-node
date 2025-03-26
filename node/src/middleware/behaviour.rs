use std::error::Error;
use std::time::Duration;
use futures::stream::StreamExt;
use libp2p::{
    kad,
    kad::{store::MemoryStore, Mode},
    mdns, noise,
    swarm::{SwarmEvent, StreamProtocol},
    tcp, yamux,
};
use libp2p::core::transport::upgrade::Authenticate;
use libp2p::identity::Keypair;
use libp2p_swarm_derive::NetworkBehaviour;
use tokio::{
    io::{self, AsyncBufReadExt},
    select,
};
use tracing_subscriber::EnvFilter;
use crate::authenticator::client::ClientBehaviour;
use crate::authenticator::musig::MusigBehaviour;

// We create a custom network behaviour that combines Kademlia and mDNS.
#[derive(NetworkBehaviour)]
pub struct AllBehaviours {
    // TODO: add bootnodes

    kademlia: kad::Behaviour<MemoryStore>,
    //mdns: mdns::tokio::Behaviour,
    client: super::authenticator::client::ClientBehaviour,
    musig: super::authenticator::musig::MusigBehaviour,

    // TODO: bitvm2 actors behaviours
}

const IPFS_PROTO_NAME: StreamProtocol = StreamProtocol::new("/ipfs/kad/1.0.0");

impl AllBehaviours {
    pub fn new(key: &Keypair) -> Self {
        let mut cfg = kad::Config::new(IPFS_PROTO_NAME);
        cfg.set_query_timeout(Duration::from_secs(5 * 60));
        let store = kad::store::MemoryStore::new(key.public().to_peer_id());
        let kademlia = kad::Behaviour::with_config(key.public().to_peer_id(), store, cfg);
        let client = ClientBehaviour::default();
        let musig = MusigBehaviour::default();
       Self {
           kademlia,
           client,
           musig,
       }
    }
}
