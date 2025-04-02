use crate::middleware::AllBehaviours;
use anyhow::Result;
use axum::body::Body;
use bitvm2_lib::actors::Actor;
use libp2p::gossipsub::MessageId;
use libp2p::{PeerId, Swarm, gossipsub};
use reqwest::Request;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tracing_subscriber::fmt::format;

#[derive(Debug, Serialize, Deserialize)]
pub struct GOATMessage {
    actor: Actor,
    content: Vec<u8>,
}

pub(crate) fn send(
    swarm: &mut Swarm<AllBehaviours>,
    message: GOATMessage,
) -> Result<MessageId, Box<dyn std::error::Error>> {
    let actor = message.actor.to_string();
    let gossipsub_topic = gossipsub::IdentTopic::new(actor);
    Ok(swarm.behaviour_mut().gossipsub.publish(gossipsub_topic, &*message.content)?)
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
    // TODO: filter the message and dispatch message to different handlers, like rpc handler, or other peers
    /// database: inner_rpc: Write or Read. For read
    /// peers: send
    Ok(())
}

///  call the rpc service
///     Method::GET/POST/PUT
pub(crate) async fn inner_rpc<S, R>(
    addr: &str,
    method: reqwest::Method,
    uri: &str,
    params: S,
) -> Result<R, Box<dyn std::error::Error>>
where
    S: Serialize,
    R: DeserializeOwned,
{
    let client = reqwest::Client::new();
    let url = reqwest::Url::parse(&format!("{addr}/{uri}"))?;

    let mut req = Request::new(method, url);
    let req_builder = reqwest::RequestBuilder::from_parts(client, req);
    let resp = req_builder.json(&params).send().await?;
    let txt = resp.text().await?;
    Ok(serde_json::from_str(txt.as_str())?)
}
