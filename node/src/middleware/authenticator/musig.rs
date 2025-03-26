use crate::kad::Event;
use std::task::{Context, Poll};
use libp2p::{Multiaddr, PeerId, StreamProtocol};
use libp2p::core::Endpoint;
use libp2p::core::transport::PortUse;
use libp2p::swarm::{handler, ConnectionDenied, ConnectionHandler, ConnectionHandlerEvent, ConnectionId, FromSwarm, NetworkBehaviour, SubstreamProtocol, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm};
use libp2p::swarm::handler::ConnectionEvent;
use libp2p_core::upgrade::ReadyUpgrade;

// client-server authentication
#[derive(Default)]
pub struct MusigBehaviour {}

impl NetworkBehaviour for MusigBehaviour {
    type ConnectionHandler = MusigHandler;
    type ToSwarm = ();

    fn handle_established_inbound_connection(&mut self, _connection_id: ConnectionId, peer: PeerId, local_addr: &Multiaddr, remote_addr: &Multiaddr) -> Result<THandler<Self>, ConnectionDenied> {
        todo!()
    }

    fn handle_established_outbound_connection(&mut self, _connection_id: ConnectionId, peer: PeerId, addr: &Multiaddr, role_override: Endpoint, port_use: PortUse) -> Result<THandler<Self>, ConnectionDenied> {
        todo!()
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        //todo!()
        println!("musig on swarm event {:?}", event);
    }

    fn on_connection_handler_event(&mut self, _peer_id: PeerId, _connection_id: ConnectionId, _event: THandlerOutEvent<Self>) {
        todo!()
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        todo!()
    }
}


pub struct MusigHandler {}

impl ConnectionHandler for MusigHandler {
    type FromBehaviour = std::convert::Infallible;
    type ToBehaviour = Result<std::time::Duration, super::Failure>;
    type InboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundProtocol = ReadyUpgrade<StreamProtocol>;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        todo!()
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>> {
        todo!()
    }

    fn on_behaviour_event(&mut self, _event: Self::FromBehaviour) {
        todo!()
    }

    fn on_connection_event(&mut self, event: ConnectionEvent<Self::InboundProtocol, Self::OutboundProtocol, Self::InboundOpenInfo, Self::OutboundOpenInfo>) {
        todo!()
    }
}