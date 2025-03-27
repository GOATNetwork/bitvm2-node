use crate::middleware::AllBehaviours;
use anyhow::Result;
use clap::builder::Str;
use libp2p::gossipsub::MessageId;
use libp2p::{PeerId, Swarm};

pub fn send(
    swarm: &mut Swarm<AllBehaviours>,
    addr: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // Dial the peer identified by the multi-address given as the second
    // command-line argument, if any.
    println!("Dialing {addr}");
    let remote: libp2p::Multiaddr = addr.parse()?;
    swarm.dial(remote)?;
    println!("Dialed {addr}");
    Ok(())
}

pub fn recv_and_dispatch(
    swarm: &mut Swarm<AllBehaviours>,
    peer_id: PeerId,
    id: MessageId,
    message: &Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "Got message: {} with id: {} from peer: {:?}",
        String::from_utf8_lossy(message),
        id,
        peer_id
    );

    Ok(())
}
