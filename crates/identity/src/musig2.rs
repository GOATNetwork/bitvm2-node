use futures::SinkExt;
use rand::RngCore;
use secp256k1::{Message, Secp256k1, SecretKey};
use std::string::String;
use std::{
    error::Error,
    net::{Ipv4Addr, Ipv6Addr},
};
use tokio::sync::mpsc::{self, Receiver, Sender};

use libp2p::{
    core::{Multiaddr, multiaddr::Protocol},
    identify, identity, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use musig2::KeyAggContext;
use musig2::k256::PublicKey;
use musig2::secp::Scalar;
use musig2::{
    AggNonce, CompactSignature, FirstRound, PartialSignature, PubNonce, SecNonce, SecNonceSpices,
    SecondRound,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use tracing_subscriber::EnvFilter;
pub static MSG_QUEUE: LazyLock<Arc<Mutex<HashMap<String, MuSig2StateMachine>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

pub struct MuSig2StateMachine {
    pub ctx: KeyAggContext,
    pub topic: String, // should be unique
    pub message: String,
    nonce_seed: [u8; 32],
    pub signer_index: usize,

    secret_key: Option<SecretKey>,

    pub first_round: Option<FirstRound>,
    pub second_round: Option<SecondRound<String>>,
}

impl MuSig2StateMachine {
    pub fn new(
        secret_key: SecretKey,
        topic: String,
        message: String,
        signer_index: usize,
        pubkeys: Vec<secp256k1::PublicKey>,
    ) -> Self {
        assert!(signer_index < pubkeys.len());
        let ctx = KeyAggContext::new(pubkeys).unwrap();
        let mut nonce_seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce_seed);

        let mut first_round = FirstRound::new(
            ctx.clone(),
            nonce_seed,
            signer_index,
            SecNonceSpices::new().with_seckey(secret_key).with_message(&message),
        )
        .unwrap();
        Self {
            ctx,
            topic,
            secret_key: Some(secret_key),
            first_round: Some(first_round),
            nonce_seed,
            message,
            signer_index,
            second_round: None,
        }
    }

    pub fn first_round_send(&self) -> PubNonce {
        self.first_round.as_ref().unwrap().our_public_nonce()
    }

    pub fn first_round_receive(&mut self, signer_index: usize, pubnonce: PubNonce) -> bool {
        self.first_round.as_mut().unwrap().receive_nonce(signer_index, pubnonce).unwrap();
        self.first_round.as_ref().unwrap().is_complete()
    }

    pub fn second_round_send(&mut self) -> PartialSignature {
        let first_round = self.first_round.take().unwrap();
        let mut second_round: SecondRound<String> =
            first_round.finalize(self.secret_key.take().unwrap(), self.message.clone()).unwrap();

        self.second_round = Some(second_round);
        self.second_round.as_mut().unwrap().our_signature()
    }

    pub fn second_round_receive(&mut self, signer_index: usize, sig: PartialSignature) -> bool {
        self.second_round.as_mut().unwrap().receive_signature(signer_index, sig).unwrap();
        self.second_round.as_ref().unwrap().is_complete()
    }
    pub fn finalize(&mut self) -> CompactSignature {
        let second_round = self.second_round.take().unwrap();
        let final_signature: CompactSignature = second_round.finalize().unwrap();
        musig2::verify_single(
            self.ctx.aggregated_pubkey::<PublicKey>(),
            final_signature,
            self.message.clone(),
        )
        .expect("aggregated signature must be valid");
        final_signature
    }
}

// all key pair can be represented by identity::keypair
pub fn generate_musig2_key() -> secp256k1::Keypair {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
    secp256k1::Keypair::from_secret_key(&secp, &secret_key)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use secp256k1::{Keypair, PublicKey};

    #[test]
    fn test_musig2_state_machine() {
        let signers: Vec<Keypair> = (0..3).map(|_| generate_musig2_key()).collect();
        let topic = "topic1".to_string();
        let message = "message1".to_string();

        let pubkeys: Vec<PublicKey> = signers.iter().map(|s| s.public_key()).collect::<Vec<_>>();

        let mut signer_state_machine = signers
            .iter()
            .enumerate()
            .map(|(idx, s)| {
                MuSig2StateMachine::new(
                    s.secret_key().clone(),
                    topic.clone(),
                    message.clone(),
                    idx,
                    pubkeys.clone(),
                )
            })
            .collect::<Vec<MuSig2StateMachine>>();

        // step 1.1: send
        let first_round =
            signer_state_machine.iter().map(|s| s.first_round_send()).collect::<Vec<PubNonce>>();

        // step 1.2: receive
        let first_round_complete = signer_state_machine
            .iter_mut()
            .enumerate()
            .map(|(idx, s)| {
                let mut is_complete = false;
                for (i, v) in first_round.iter().enumerate() {
                    if i != idx {
                        is_complete = s.first_round_receive(i, v.clone());
                    }
                }
                is_complete
            })
            .collect::<Vec<bool>>();

        assert!(first_round_complete.iter().all(|x| *x));

        // step 2.1
        let second_round = signer_state_machine
            .iter_mut()
            .map(|s| s.second_round_send())
            .collect::<Vec<PartialSignature>>();

        // step 2.2
        let second_round_complete = signer_state_machine
            .iter_mut()
            .enumerate()
            .map(|(idx, s)| {
                let mut is_complete = false;
                for (i, v) in second_round.iter().enumerate() {
                    if i != idx {
                        is_complete = s.second_round_receive(i, v.clone());
                    }
                }
                is_complete
            })
            .collect::<Vec<bool>>();

        assert!(second_round_complete.iter().all(|x| *x));

        signer_state_machine.iter_mut().for_each(|s| {
            s.finalize();
        })
    }
}
