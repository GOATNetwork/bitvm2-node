use crate::metrics_service::MetricService;
use futures::{
    future::{BoxFuture, Either},
    prelude::*,
};
use libp2p::core::Endpoint;
use libp2p::core::transport::PortUse;
use libp2p::swarm::handler::ConnectionEvent;
use libp2p::swarm::{
    ConnectionDenied, ConnectionHandler, ConnectionHandlerEvent, ConnectionId, FromSwarm,
    NetworkBehaviour, Stream, SubstreamProtocol, THandler, THandlerInEvent, THandlerOutEvent,
    ToSwarm, handler,
};
use libp2p::{Multiaddr, PeerId, StreamProtocol};
use libp2p_core::upgrade::ReadyUpgrade;
use musig2::KeyAggContext;
use std::collections::VecDeque;
use std::num::IntErrorKind::PosOverflow;
use std::task::{Context, Poll};

// client-server authentication
#[derive(Default)]
pub struct MusigBehaviour {
    n_parties: usize,
    events: VecDeque<Event>,
}

/// handle the n-of-n key generation or signing
#[derive(Debug)]
pub struct Event {
    /// The peer ID of the remote.
    pub peer: PeerId,
    /// The connection the ping was executed on.
    pub connection: ConnectionId,
    /// The result of an inbound or outbound ping.
    pub result: Result<Vec<u8>, super::Failure>,
}

pub const PROTOCOL_NAME: StreamProtocol = StreamProtocol::new("/libp2p/musig2/1.0.0");
impl NetworkBehaviour for MusigBehaviour {
    type ConnectionHandler = MusigHandler;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        println!("connection in bound: {:?} {:?} {:?}", peer, local_addr, remote_addr);
        Ok(MusigHandler::new())
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        println!("connection out bound: {:?} {:?} {:?}", connection_id, peer, addr);
        Ok(MusigHandler::new())
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        println!("musig on swarm event {:?}", event);
    }

    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
        result: THandlerOutEvent<Self>,
    ) {
        println!("musig on handler event {:?} {:?} {:?}", peer, connection, result);
        self.events.push_front(Event { peer, connection, result })
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(e) = self.events.pop_back() {
            Poll::Ready(ToSwarm::GenerateEvent(e))
        } else {
            Poll::Pending
        }
    }
}

type PingFuture = BoxFuture<'static, Result<(Stream, Vec<u8>), super::Failure>>;
type PongFuture = BoxFuture<'static, Result<Stream, std::io::Error>>;
/// The current state w.r.t. outbound pings.
enum OutboundState {
    /// A new substream is being negotiated for the ping protocol.
    OpenStream,
    /// The substream is idle, waiting to send the next ping.
    Idle(Stream),
    /// A ping is being sent and the response awaited.
    Ping(PingFuture),
}
pub struct MusigHandler {
    /// Outbound ping failures that are pending to be processed by `poll()`.
    pending_errors: VecDeque<super::Failure>,
    /// The number of consecutive ping failures that occurred.
    ///
    /// Each successful ping resets this counter to 0.
    failures: u32,
    /// The outbound ping state.
    outbound: Option<OutboundState>,
    /// The inbound pong handler, i.e. if there is an inbound
    /// substream, this is always a future that waits for the
    /// next inbound ping to be answered.
    inbound: Option<PongFuture>,
    /// Tracks the state of our handler.
    state: State,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// We are inactive because the other peer doesn't support ping.
    Inactive {
        /// Whether or not we've reported the missing support yet.
        ///
        /// This is used to avoid repeated events being emitted for a specific connection.
        reported: bool,
    },
    /// We are actively pinging the other peer.
    Active,
}

impl MusigHandler {
    /// Builds a new [`Handler`] with the given configuration.
    pub fn new() -> Self {
        MusigHandler {
            pending_errors: VecDeque::with_capacity(2),
            failures: 0,
            outbound: None,
            inbound: None,
            state: State::Active,
        }
    }
}

impl ConnectionHandler for MusigHandler {
    type FromBehaviour = std::convert::Infallible;
    type ToBehaviour = Result<Vec<u8>, super::Failure>;
    type InboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundProtocol = ReadyUpgrade<StreamProtocol>;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        println!("musig listening protocol");
        SubstreamProtocol::new(ReadyUpgrade::new(PROTOCOL_NAME), ())
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        // TODO: return the result
        println!("mulsig poll");
        match self.state {
            State::Inactive { reported: true } => {
                return Poll::Pending; // nothing to do on this connection
            }
            State::Inactive { reported: false } => {
                self.state = State::Inactive { reported: true };
                return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(Err(
                    super::Failure::Unsupported,
                )));
            }
            State::Active => {}
        }

        // Respond to inbound pings.
        if let Some(fut) = self.inbound.as_mut() {
            match fut.poll_unpin(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    tracing::debug!("Inbound ping error: {:?}", e);
                    self.inbound = None;
                }
                Poll::Ready(Ok(stream)) => {
                    tracing::trace!("answered inbound ping from peer");

                    todo!();
                    // A ping from a remote peer has been answered, wait for the next.
                    //self.inbound = Some(stream);
                }
            }
        }

        loop {
            // Check for outbound ping failures.
            if let Some(error) = self.pending_errors.pop_back() {
                tracing::debug!("Ping failure: {:?}", error);

                self.failures += 1;

                // Note: For backward-compatibility the first failure is always "free"
                // and silent. This allows peers who use a new substream
                // for each ping to have successful ping exchanges with peers
                // that use a single substream, since every successful ping
                // resets `failures` to `0`.
                if self.failures > 1 {
                    return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(Err(error)));
                }
            }

            // Continue outbound pings.
            match self.outbound.take() {
                Some(OutboundState::Ping(mut ping)) => match ping.poll_unpin(cx) {
                    Poll::Pending => {
                        self.outbound = Some(OutboundState::Ping(ping));
                        break;
                    }
                    Poll::Ready(Ok((stream, rtt))) => {
                        tracing::debug!(?rtt, "ping succeeded");
                        self.failures = 0;
                        self.outbound = Some(OutboundState::Idle(stream));
                        return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(Ok(rtt)));
                    }
                    Poll::Ready(Err(e)) => {
                        self.pending_errors.push_front(e);
                    }
                },
                Some(OutboundState::Idle(stream)) => {
                    todo!()
                }
                Some(OutboundState::OpenStream) => {
                    self.outbound = Some(OutboundState::OpenStream);
                    break;
                }
                None => {
                    todo!()
                }
            }
        }

        Poll::Pending
    }

    fn on_behaviour_event(&mut self, _event: Self::FromBehaviour) {
        todo!()
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<
            Self::InboundProtocol,
            Self::OutboundProtocol,
            Self::InboundOpenInfo,
            Self::OutboundOpenInfo,
        >,
    ) {
        println!("musig handler connection event: {:?}", event);
    }
}

/// A wrapper around [`protocol::send_ping`] that enforces a time out.
async fn send_ping(stream: Stream, msg: Vec<u8>) -> Result<(Stream, Vec<u8>), super::Failure> {
    todo!()
    //let ping = protocol::send_ping(stream);
    //futures::pin_mut!(ping);

    //match future::select(ping, msg).await {
    //    Either::Left((Ok((stream, rtt)), _)) => Ok((stream, rtt)),
    //    Either::Left((Err(e), _)) => Err(Failure::other(e)),
    //    Either::Right(((), _)) => Err(Failure::Timeout),
    //}
}
