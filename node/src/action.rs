use clap::builder::Str;
use libp2p::Swarm;
use crate::middleware::AllBehaviours;

pub fn action(swarm: &mut Swarm<AllBehaviours>, addr: String) -> Result<(), Box<dyn std::error::Error>> {
    // Dial the peer identified by the multi-address given as the second
    // command-line argument, if any.
    println!("Dialing {addr}");
    let remote: libp2p::Multiaddr = addr.parse()?;
    swarm.dial(remote)?;
    println!("Dialed {addr}");
    return Ok(());
}