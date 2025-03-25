use std::{error::Error, time::Duration};

use tracing_subscriber::EnvFilter;
use libp2p::{noise, tcp, yamux, ping, swarm::SwarmEvent};
use libp2p::futures::StreamExt;

use bitvm2_lib::actors::Actor;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // load role
    let actor = std::env::var("ACTOR").unwrap();
    let actor = Actor::try_from(actor.as_str()).unwrap();
    println!("actor: {:?}", actor);

    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|_|ping::Behaviour::default())?
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

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {address:?}"),
            SwarmEvent::Behaviour(event) => println!("{event:?}"),
            _ => {}
        }
    }
    Ok(())
}
