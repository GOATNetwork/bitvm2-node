use crate::middleware::AllBehaviours;
use anyhow::Result;
use axum::body::Body;
use bitcoin::{PublicKey, XKeyIdentifier};
use bitvm2_lib::actors::Actor;
use bitvm2_lib::verifier::export_challenge_tx;
use futures::AsyncRead;
use goat::transactions::assert::utils::COMMIT_TX_NUM;
use libp2p::gossipsub::{Message, MessageId};
use libp2p::{PeerId, Swarm, gossipsub};
use musig2::{AggNonce, PartialSignature, PubNonce, SecNonce};
use reqwest::Request;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use todo_funcs::{check_l2_status, get_graph, is_my_graph, update_graph};
use tracing_subscriber::fmt::format;
use uuid::Uuid;
use bitcoin::{key::Keypair, Amount, Network, OutPoint, Txid};
use bitvm2_lib::types::{Bitvm2Graph, Bitvm2Parameters, CustomInputs, Groth16Proof, PublicInputs, VerifyingKey};
use bitvm2_lib::{operator::*, committee::*, verifier::*};


#[derive(Debug, Serialize, Deserialize)]
pub struct GOATMessage {
    pub actor: Actor,
    pub content: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub enum GOATMessageContent {
    CreateInstance(CreateInstance),
    CreateGraphPrepare(CreateGraphPrepare),
    CreateGraph(CreateGraph),
    NonceGeneration(NonceGeneration),
    CommitteePresign(CommitteePresign),
    BridgeInFinalize(BridgeInFinalize),
    KickoffReady(KickoffReady),
    KickoffSent(KickoffSent),
    Take1Ready(Take1Ready),
    Take1Sent(Take1Sent),
    ChallengeSent(ChallengeSent),
    AssertSent(AssertSent),
    Take2Ready(Take2Ready),
    Take2Sent(Take2Sent),
    DisproveSent(DisproveSent),
}

#[derive(Serialize, Deserialize)]
pub struct CreateInstance {
    pub instance_id: Uuid,
    pub network: Network,
    pub depositor_evm_address: [u8; 20],
    pub pegin_amount: Amount,
    pub user_inputs: CustomInputs,
}

#[derive(Serialize, Deserialize)]
pub struct CreateGraphPrepare {
    pub instance_id: Uuid,
    pub network: Network,
    pub depositor_evm_address: [u8; 20],
    pub pegin_amount: Amount,
    pub user_inputs: CustomInputs,
    pub committee_member_pubkey: PublicKey,
}

#[derive(Serialize, Deserialize)]
pub struct CreateGraph {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub graph: Bitvm2Graph,
}

#[derive(Serialize, Deserialize)]
pub struct NonceGeneration {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub pub_nonces: [PubNonce; COMMITTEE_PRE_SIGN_NUM],
}

#[derive(Serialize, Deserialize)]
pub struct CommitteePresign {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub committee_partial_sigs: [PartialSignature; COMMITTEE_PRE_SIGN_NUM],
    pub agg_nonces: [AggNonce; COMMITTEE_PRE_SIGN_NUM],
}

#[derive(Serialize, Deserialize)]
pub struct BridgeInFinalize {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub graph: Bitvm2Graph,
}

#[derive(Serialize, Deserialize)]
pub struct KickoffReady {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub withdraw_evm_txid: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct KickoffSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub kickoff_txid: Txid,
}

#[derive(Serialize, Deserialize)]
pub struct ChallengeSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub challenge_txid: Txid,
}

#[derive(Serialize, Deserialize)]
pub struct AssertSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub assert_init_txid: Txid,
    pub assert_commit_txids: [Txid; COMMIT_TX_NUM],
    pub assert_final_txid: Txid,
}

#[derive(Serialize, Deserialize)]
pub struct Take1Ready {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}

#[derive(Serialize, Deserialize)]
pub struct Take1Sent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub take1_txid: Txid,
}

#[derive(Serialize, Deserialize)]
pub struct Take2Ready {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}

#[derive(Serialize, Deserialize)]
pub struct Take2Sent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub take2_txid: Txid,
}

#[derive(Serialize, Deserialize)]
pub struct DisproveSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub disprove_txid: Txid,
}

impl GOATMessage {
    pub fn from_typed<T: Serialize>(actor: Actor, value: &T) -> Result<Self, serde_json::Error> {
        let content = serde_json::to_vec(value)?;
        Ok(Self { actor, content })
    }

    pub fn to_typed<T: for<'de> Deserialize<'de>>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.content)
    }

    pub fn default_message_id() -> MessageId {
        MessageId(b"__inner_message_id__".to_vec())
    }
}

pub mod  bitvm_key_derivation {
    use super::*;
    use libp2p::identity::Keypair as P2pKeypair;
    use bitvm2_lib::{
        committee::{generate_keypair_from_seed, generate_nonce_from_seed, COMMITTEE_PRE_SIGN_NUM}, 
        operator::generate_wots_keys,
        types::{WotsPublicKeys, WotsSecretKeys},
    };
    use musig2::{PubNonce, SecNonce, secp256k1::schnorr::Signature};

    fn hex_encode(bytes: Vec<u8>) -> String {
        bytes.iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    pub struct CommitteeMasterKey(P2pKeypair);
    impl CommitteeMasterKey {
        pub fn new(inner: P2pKeypair) -> Self {
            CommitteeMasterKey(inner)
        }
        pub fn keypair_for_instance(&self, instance_id: Uuid) -> Keypair {
            let domain = vec![b"committee_bitvm_key".to_vec(), instance_id.as_bytes().to_vec()].concat();
            let seed = self.0.derive_secret(&domain).unwrap();
            generate_keypair_from_seed(hex_encode(seed.to_vec()))
        }
        pub fn nonces_for_graph(&self, instance_id: Uuid, graph_id: Uuid) -> [(SecNonce, PubNonce, Signature); COMMITTEE_PRE_SIGN_NUM] {
            let domain = vec![b"committee_bitvm_nonces".to_vec(), instance_id.as_bytes().to_vec(), graph_id.as_bytes().to_vec()].concat();
            let seed = self.0.derive_secret(&domain).unwrap();
            let signer_keypair = self.keypair_for_instance(instance_id);
            generate_nonce_from_seed(hex_encode(seed.to_vec()), graph_id.as_u128() as usize, signer_keypair)
        }
    }

    pub struct OperatorMasterKey(P2pKeypair);
    impl OperatorMasterKey {
        pub fn new(inner: P2pKeypair) -> Self {
            OperatorMasterKey(inner)
        }
        pub fn keypair_for_graph(&self, graph_id: Uuid) -> Keypair {
            let domain = vec![b"operator_bitvm_key".to_vec(), graph_id.as_bytes().to_vec()].concat();
            let seed = self.0.derive_secret(&domain).unwrap();
            generate_keypair_from_seed(hex_encode(seed.to_vec()))
        }
        pub fn wots_keypair_for_graph(&self, graph_id: Uuid) -> (WotsSecretKeys, WotsPublicKeys) {
            let domain = vec![b"operator_bitvm_wots_key".to_vec(), graph_id.as_bytes().to_vec()].concat();
            let seed = self.0.derive_secret(&domain).unwrap();
            generate_wots_keys(&hex_encode(seed.to_vec()))
        }
    }
}

#[allow(unused_variables)]
pub mod todo_funcs {
    use super::*;
    use base64::Engine;
    use bitcoin::{Transaction, Address};
    use zeroize::Zeroizing;
    use libp2p::identity::Keypair as P2pKeypair;
    use std::str::FromStr;
    use goat::transactions::base::Input;
    use goat::scripts::generate_burn_script_address;
    use bitvm::treepp::*;

    pub fn get_local_key() -> Result<P2pKeypair, Box<dyn std::error::Error>> {
        let local_key = std::env::var("KEY").expect("KEY is missing");

        Ok(libp2p::identity::Keypair::from_protobuf_encoding(&Zeroizing::new(
            base64::engine::general_purpose::STANDARD.decode(local_key)?,
        ))?)
    }

    pub fn committee_member_num() -> usize {
        2
    }

    pub fn store_committee_pubkey(instance_id: Uuid, pubkey: PublicKey) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    pub fn get_committee_pubkeys(instance_id: Uuid) -> Result<Vec<PublicKey>, Box<dyn std::error::Error>> {
        Ok(vec![])
    }

    pub fn should_generate_graph(create_graph_prepare_data: &CreateGraphPrepare) -> bool {
        true
    }

    pub fn is_my_graph(instance_id: Uuid, graph_id: Uuid) -> bool {
        true
    }

    pub fn check_l2_status(instance_id: Uuid, graph_id: Uuid) -> bool {
        true
    }

    pub fn store_committee_pub_nonces(instance_id: Uuid, graph_id: Uuid, committee_pubkey: PublicKey, pub_nonces: [PubNonce; COMMITTEE_PRE_SIGN_NUM]) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    pub fn get_committee_pub_nonces(instance_id: Uuid, graph_id: Uuid) -> Result<Vec<[PubNonce; COMMITTEE_PRE_SIGN_NUM]>, Box<dyn std::error::Error>> {
        Ok(vec![])
    }

    pub fn store_committee_partial_sigs(instance_id: Uuid, graph_id: Uuid, committee_pubkey: PublicKey, partial_sigs: [PartialSignature; COMMITTEE_PRE_SIGN_NUM]) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    pub fn get_committee_partial_sigs(instance_id: Uuid, graph_id: Uuid) -> Result<Vec<[PartialSignature; COMMITTEE_PRE_SIGN_NUM]>, Box<dyn std::error::Error>> {
        Ok(vec![])
    }

    pub fn store_graph(instance_id: Uuid, graph_id: Uuid, graph: &Bitvm2Graph) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    pub fn update_graph(instance_id: Uuid, graph_id: Uuid, graph: &Bitvm2Graph) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    pub fn get_graph(instance_id: Uuid, graph_id: Uuid) -> Result<Bitvm2Graph, Box<dyn std::error::Error>> {
        Err("TODO".into())
    }

    pub fn get_stake_amount() -> Amount {
        Amount::from_sat(20000000)
    }

    pub fn get_challenge_amount() -> Amount {
        Amount::from_sat(20000000)
    }

    pub fn get_operator_inputs(stake_amount: Amount) -> CustomInputs {
        let mock_input = Input {
            outpoint: OutPoint {
                txid: Txid::from_str("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d").unwrap(),
                vout: 0,
            },
            amount: Amount::from_btc(10000.0).unwrap(),
        };
        let mock_user_change_address = generate_burn_script_address(Network::Testnet);
        CustomInputs {
            inputs: vec![mock_input.clone()],
            input_amount: stake_amount,
            fee_amount: Amount::from_sat(1000),
            change_address: mock_user_change_address,
        }
    }

    pub fn get_partial_scripts() -> Vec<Script> {
        vec![]
    }

    pub fn broadcast_tx(tx: Transaction) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    pub fn disprove_reward_address() -> Result<Address, Box<dyn std::error::Error>> {
        Err("TODO".into())
    }

    pub fn complete_and_broadcast_challenge_tx(tx: Transaction) -> Result<Txid, Box<dyn std::error::Error>> {
        Ok(Txid::from_str("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d")?)
    }

    pub fn validate_kickoff(kickoff_txid: Txid) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(true)
    }

    pub fn validate_challenge(challenge_txid: Txid) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(true)
    }

    pub fn get_groth16_proof(instance_id: Uuid, graph_id: Uuid) -> Result<(Groth16Proof, PublicInputs, VerifyingKey), Box<dyn std::error::Error>> {
        Err("TODO".into())
    }

    pub fn validate_assert(assert_commit_txns: [Txid; COMMIT_TX_NUM]) -> Result<Option<(usize, Script)>, Box<dyn std::error::Error>> {
        Err("TODO".into())
    }
}

/// Filter the message and dispatch message to different handlers, like rpc handler, or other peers
///     * database: inner_rpc: Write or Read.
///     * peers: send
pub fn recv_and_dispatch(
    swarm: &mut Swarm<AllBehaviours>,
    actor: Actor,
    peer_id: PeerId,
    id: MessageId,
    message: &Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!(
        "Got message: {} with id: {} from peer: {:?}",
        String::from_utf8_lossy(message),
        id,
        peer_id
    );
    let default_message_id = GOATMessage::default_message_id();
    if id == default_message_id {
        tracing::debug!("Get the running task, and broadcast the task status or result");
        // TODO
        return Ok(());
    }
    let message: GOATMessage = serde_json::from_slice(&message)?;
    println!("Received message: {:?}", message);
    if message.actor != actor {
        return Ok(());
    }
    println!("Handle message: {:?}", message);
    let content: GOATMessageContent = message.to_typed()?;
    match (content, actor) {
        (GOATMessageContent::CreateInstance(receive_data), Actor::Committee) => {
            let instance_id = receive_data.instance_id;
            let master_key = bitvm_key_derivation::CommitteeMasterKey::new(todo_funcs::get_local_key()?);
            let keypair = master_key.keypair_for_instance(instance_id);
            let message_content = GOATMessageContent::CreateGraphPrepare(CreateGraphPrepare {
                instance_id,
                network: receive_data.network,
                pegin_amount: receive_data.pegin_amount,
                depositor_evm_address: receive_data.depositor_evm_address,
                user_inputs: receive_data.user_inputs,
                committee_member_pubkey: keypair.public_key().into(),
            });
            todo_funcs::store_committee_pubkey(receive_data.instance_id, keypair.public_key().into())?;
            send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
            send_to_peer(swarm, GOATMessage::from_typed(Actor::Operator, &message_content)?)?;
        },
        (GOATMessageContent::CreateGraphPrepare(receive_data), Actor::Operator) => {
            todo_funcs::store_committee_pubkey(receive_data.instance_id, receive_data.committee_member_pubkey)?;
            let collected_keys = todo_funcs::get_committee_pubkeys(receive_data.instance_id)?;
            if  todo_funcs::should_generate_graph(&receive_data) 
                && collected_keys.len() == todo_funcs::committee_member_num() 
            {
                let graph_id = Uuid::new_v4();
                let master_key = bitvm_key_derivation::OperatorMasterKey::new(todo_funcs::get_local_key()?);
                let keypair = master_key.keypair_for_graph(graph_id);
                let (_, operator_wots_pubkeys) = master_key.wots_keypair_for_graph(graph_id);
                let committee_agg_pubkey = key_aggregation(&collected_keys);
                let disprove_scripts = generate_disprove_scripts(&todo_funcs::get_partial_scripts(), &operator_wots_pubkeys);
                let params = Bitvm2Parameters {
                    network: receive_data.network,
                    depositor_evm_address: receive_data.depositor_evm_address,
                    pegin_amount: receive_data.pegin_amount,
                    user_inputs: receive_data.user_inputs,
                    stake_amount: todo_funcs::get_stake_amount(),
                    challenge_amount: todo_funcs::get_challenge_amount(),
                    committee_pubkeys: collected_keys,
                    committee_agg_pubkey,   
                    operator_pubkey: keypair.public_key().into(),
                    operator_wots_pubkeys,
                    operator_inputs: todo_funcs::get_operator_inputs(todo_funcs::get_stake_amount()),
                };
                let disprove_scripts_bytes = disprove_scripts.iter().map(|x| x.clone().compile().into_bytes()).collect();
                let mut graph = generate_bitvm_graph(params, disprove_scripts_bytes)?;
                operator_pre_sign(keypair, &mut graph)?;
                todo_funcs::store_graph(receive_data.instance_id, graph_id, &graph)?;
                let message_content = GOATMessageContent::CreateGraph(CreateGraph {
                    instance_id: receive_data.instance_id,
                    graph_id,
                    graph,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
            };
        },
        (GOATMessageContent::CreateGraph(receive_data), Actor::Committee) => {
            todo_funcs::store_graph(receive_data.instance_id, receive_data.graph_id, &receive_data.graph)?;
            let master_key = bitvm_key_derivation::CommitteeMasterKey::new(todo_funcs::get_local_key()?);
            let nonces = master_key.nonces_for_graph(receive_data.instance_id, receive_data.graph_id);
            let keypair = master_key.keypair_for_instance(receive_data.instance_id);
            let pub_nonces: [PubNonce; COMMITTEE_PRE_SIGN_NUM] = std::array::from_fn(|i| nonces[i].1.clone());
            let message_content = GOATMessageContent::NonceGeneration(NonceGeneration {
                instance_id: receive_data.instance_id,
                graph_id: receive_data.graph_id,
                committee_pubkey: keypair.public_key().into(),
                pub_nonces,
            });
            send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
        },
        (GOATMessageContent::NonceGeneration(receive_data), Actor::Committee) => {
            todo_funcs::store_committee_pub_nonces(receive_data.instance_id, receive_data.graph_id, receive_data.committee_pubkey, receive_data.pub_nonces)?;
            let graph = todo_funcs::get_graph(receive_data.instance_id, receive_data.graph_id)?;
            let master_key = bitvm_key_derivation::CommitteeMasterKey::new(todo_funcs::get_local_key()?);
            let keypair = master_key.keypair_for_instance(receive_data.instance_id);
            let nonces = master_key.nonces_for_graph(receive_data.instance_id, receive_data.graph_id);
            let sec_nonces: [SecNonce; COMMITTEE_PRE_SIGN_NUM] = std::array::from_fn(|i| nonces[i].0.clone());
            let collected_pub_nonces = todo_funcs::get_committee_pub_nonces(receive_data.instance_id, receive_data.graph_id)?;
            if collected_pub_nonces.len() == todo_funcs::committee_member_num() {
                let agg_nonces = nonces_aggregation(collected_pub_nonces);
                let committee_partial_sigs = committee_pre_sign(keypair, sec_nonces, agg_nonces.clone(), &graph)?;
                let message_content = GOATMessageContent::CommitteePresign(CommitteePresign {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    committee_pubkey: receive_data.committee_pubkey,
                    committee_partial_sigs,
                    agg_nonces,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
            };
        },
        (GOATMessageContent::CommitteePresign(receive_data), Actor::Committee) => {
            todo_funcs::store_committee_partial_sigs(receive_data.instance_id, receive_data.graph_id, receive_data.committee_pubkey, receive_data.committee_partial_sigs)?;
            let collected_partial_sigs = todo_funcs::get_committee_partial_sigs(receive_data.instance_id, receive_data.graph_id)?;
            if collected_partial_sigs.len() == todo_funcs::committee_member_num() {
                let mut grouped_partial_sigs: [Vec<PartialSignature>; COMMITTEE_PRE_SIGN_NUM] = Default::default();
                for partial_sigs in collected_partial_sigs {
                    for (i, sig) in partial_sigs.into_iter().enumerate() {
                        grouped_partial_sigs[i].push(sig);
                    }
                };
                let mut graph = get_graph(receive_data.instance_id, receive_data.graph_id)?;
                signature_aggregation_and_push(&grouped_partial_sigs, &receive_data.agg_nonces, &mut graph)?;
                update_graph(receive_data.instance_id, receive_data.graph_id, &graph)?;
                let message_content = GOATMessageContent::BridgeInFinalize(BridgeInFinalize {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    graph,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
            }
        },
        (GOATMessageContent::BridgeInFinalize(receive_data), _) => {
            todo_funcs::store_graph(receive_data.instance_id, receive_data.graph_id, &receive_data.graph)?;
        },
        (GOATMessageContent::KickoffReady(receive_data), Actor::Operator) => {
            if is_my_graph(receive_data.instance_id, receive_data.graph_id) 
                && check_l2_status(receive_data.instance_id, receive_data.graph_id) 
            {
                let mut graph = todo_funcs::get_graph(receive_data.instance_id, receive_data.graph_id)?;
                let master_key = bitvm_key_derivation::OperatorMasterKey::new(todo_funcs::get_local_key()?);
                let keypair = master_key.keypair_for_graph(receive_data.graph_id);
                let (operator_wots_seckeys,operator_wots_pubkeys) = master_key.wots_keypair_for_graph(receive_data.graph_id);
                let kickoff_tx = operator_sign_kickoff(keypair, &mut graph, &operator_wots_seckeys, &operator_wots_pubkeys, receive_data.withdraw_evm_txid)?;
                let kickoff_txid = kickoff_tx.compute_txid();
                todo_funcs::broadcast_tx(kickoff_tx)?;
                let message_content = GOATMessageContent::KickoffSent(KickoffSent {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    kickoff_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Challenger, &message_content)?)?;
            }
        },
        (GOATMessageContent::Take1Ready(receive_data), Actor::Operator) => {
            if is_my_graph(receive_data.instance_id, receive_data.graph_id) {
                let mut graph = todo_funcs::get_graph(receive_data.instance_id, receive_data.graph_id)?;
                let master_key = bitvm_key_derivation::OperatorMasterKey::new(todo_funcs::get_local_key()?);
                let keypair = master_key.keypair_for_graph(receive_data.graph_id);
                let take1_tx = operator_sign_take1(keypair, &mut graph)?;
                let take1_txid = take1_tx.compute_txid();
                todo_funcs::broadcast_tx(take1_tx)?;
                let message_content = GOATMessageContent::Take1Sent(Take1Sent {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    take1_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
            }
        },
        (GOATMessageContent::KickoffSent(receive_data), Actor::Challenger) => {
            if !todo_funcs::validate_kickoff(receive_data.kickoff_txid)? {
                let mut graph = todo_funcs::get_graph(receive_data.instance_id, receive_data.graph_id)?;
                let challenge_tx = export_challenge_tx(&mut graph)?;
                let challenge_txid = todo_funcs::complete_and_broadcast_challenge_tx(challenge_tx)?;
                let message_content = GOATMessageContent::ChallengeSent(ChallengeSent {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    challenge_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Operator, &message_content)?)?;

            }
        },
        (GOATMessageContent::ChallengeSent(receive_data), Actor::Operator) => {
            if is_my_graph(receive_data.instance_id, receive_data.graph_id) 
                && todo_funcs::validate_challenge(receive_data.challenge_txid)? 
            {
                let mut graph = todo_funcs::get_graph(receive_data.instance_id, receive_data.graph_id)?;
                let master_key = bitvm_key_derivation::OperatorMasterKey::new(todo_funcs::get_local_key()?);
                let keypair = master_key.keypair_for_graph(receive_data.graph_id);
                let (operator_wots_seckeys,operator_wots_pubkeys) = master_key.wots_keypair_for_graph(receive_data.graph_id);
                let (proof, pubin, vk) = todo_funcs::get_groth16_proof(receive_data.instance_id, receive_data.graph_id)?;
                let proof_sigs = sign_proof(&vk, proof, pubin, &operator_wots_seckeys);
                let (assert_init_tx, assert_commit_txns, assert_final_tx) = operator_sign_assert(keypair, &mut graph, &operator_wots_pubkeys, proof_sigs)?;
                let assert_init_txid = assert_init_tx.compute_txid();
                todo_funcs::broadcast_tx(assert_init_tx)?;
                let mut assert_commit_txids = Vec::with_capacity(COMMIT_TX_NUM);
                for tx in assert_commit_txns {        
                    assert_commit_txids.push(tx.compute_txid());
                    todo_funcs::broadcast_tx(tx)?;    
                };
                let assert_final_txid = assert_final_tx.compute_txid();
                todo_funcs::broadcast_tx(assert_final_tx)?;
                let message_content = GOATMessageContent::AssertSent(AssertSent {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    assert_init_txid,
                    assert_commit_txids: assert_commit_txids.try_into().unwrap(),
                    assert_final_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Challenger, &message_content)?)?;
            }
        },
        (GOATMessageContent::Take2Ready(receive_data), Actor::Operator) => {
            if is_my_graph(receive_data.instance_id, receive_data.graph_id) {
                let mut graph = todo_funcs::get_graph(receive_data.instance_id, receive_data.graph_id)?;
                let master_key = bitvm_key_derivation::OperatorMasterKey::new(todo_funcs::get_local_key()?);
                let keypair = master_key.keypair_for_graph(receive_data.graph_id);
                let take2_tx = operator_sign_take2(keypair, &mut graph)?;
                let take2_txid = take2_tx.compute_txid();
                todo_funcs::broadcast_tx(take2_tx)?;
                let message_content = GOATMessageContent::Take2Sent(Take2Sent {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    take2_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
            }
        },
        (GOATMessageContent::AssertSent(receive_data), Actor::Challenger) => {
            if let Some(disprove_witness) = todo_funcs::validate_assert(receive_data.assert_commit_txids)? {
                let mut graph = todo_funcs::get_graph(receive_data.instance_id, receive_data.graph_id)?;
                let disprove_scripts = generate_disprove_scripts(&todo_funcs::get_partial_scripts(), &graph.parameters.operator_wots_pubkeys);
                let disprove_scripts_bytes = disprove_scripts.iter().map(|x| x.clone().compile().into_bytes()).collect();
                let assert_wots_pubkeys = graph.parameters.operator_wots_pubkeys.1.clone();
                let disprove_tx = sign_disprove(&mut graph, disprove_witness, disprove_scripts_bytes, &assert_wots_pubkeys, todo_funcs::disprove_reward_address()?)?;
                let disprove_txid = disprove_tx.compute_txid();
                todo_funcs::broadcast_tx(disprove_tx)?;
                let message_content = GOATMessageContent::DisproveSent(DisproveSent {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    disprove_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
            }
        },
        _ => {}
    }
    // TODO
    Ok(())
}

pub(crate) fn send_to_peer(
    swarm: &mut Swarm<AllBehaviours>,
    message: GOATMessage,
) -> Result<MessageId, Box<dyn std::error::Error>> {
    let actor = message.actor.to_string();
    let gossipsub_topic = gossipsub::IdentTopic::new(actor);
    Ok(swarm.behaviour_mut().gossipsub.publish(gossipsub_topic, &*message.content)?)
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
