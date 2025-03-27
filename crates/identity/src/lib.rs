use std::{
    error::Error,
    net::{Ipv4Addr, Ipv6Addr},
};

use futures::StreamExt;
use libp2p::{
    core::{Multiaddr, multiaddr::Protocol},
    identify, identity, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use tracing_subscriber::EnvFilter;

pub fn generate_local_key() -> identity::Keypair {
    identity::Keypair::generate_ed25519()
}

fn generate_musig2_key() {}
