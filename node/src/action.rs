use crate::middleware::AllBehaviours;
use anyhow::Result;
use axum::body::Body;
use bitcoin::{Amount, Network, OutPoint, Txid, key::Keypair};
use bitcoin::{PublicKey, XKeyIdentifier};
use bitvm2_lib::actors::Actor;
use bitvm2_lib::types::{
    Bitvm2Graph, Bitvm2Parameters, CustomInputs, Groth16Proof, PublicInputs, VerifyingKey,
};
use bitvm2_lib::verifier::export_challenge_tx;
use bitvm2_lib::{committee::*, operator::*, verifier::*};
use futures::AsyncRead;
use goat::transactions::{assert::utils::COMMIT_TX_NUM, pre_signed::PreSignedTransaction};
use libp2p::gossipsub::{Message, MessageId};
use libp2p::{PeerId, Swarm, gossipsub};
use musig2::{AggNonce, PartialSignature, PubNonce, SecNonce};
use reqwest::Request;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tracing_subscriber::fmt::format;
use uuid::Uuid;

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
    GraphFinalize(GraphFinalize),
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
    pub committee_members_num: usize,
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
    pub committee_members_num: usize,
}

#[derive(Serialize, Deserialize)]
pub struct CommitteePresign {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub committee_partial_sigs: [PartialSignature; COMMITTEE_PRE_SIGN_NUM],
    pub agg_nonces: [AggNonce; COMMITTEE_PRE_SIGN_NUM],
    pub committee_members_num: usize,
}

#[derive(Serialize, Deserialize)]
pub struct GraphFinalize {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub graph: Bitvm2Graph,
}

#[derive(Serialize, Deserialize)]
pub struct KickoffReady {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
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

pub mod bitvm_key_derivation {
    use super::*;
    use bitvm2_lib::{
        committee::{COMMITTEE_PRE_SIGN_NUM, generate_keypair_from_seed, generate_nonce_from_seed},
        operator::generate_wots_keys,
        types::{WotsPublicKeys, WotsSecretKeys},
    };
    use musig2::{PubNonce, SecNonce, secp256k1::schnorr::Signature};
    use sha2::{Digest, Sha256};

    fn derive_secret(master_key: &Keypair, domain: &Vec<u8>) -> String {
        let secret_key = master_key.secret_key();
        let mut hasher = Sha256::new();
        hasher.update(secret_key.secret_bytes());
        hasher.update(domain);
        format!("{:x}", hasher.finalize())
    }

    pub struct CommitteeMasterKey(Keypair);
    impl CommitteeMasterKey {
        pub fn new(inner: Keypair) -> Self {
            CommitteeMasterKey(inner)
        }
        pub fn keypair_for_instance(&self, instance_id: Uuid) -> Keypair {
            let domain =
                vec![b"committee_bitvm_key".to_vec(), instance_id.as_bytes().to_vec()].concat();
            let instance_seed = derive_secret(&self.0, &domain);
            generate_keypair_from_seed(instance_seed)
        }
        pub fn nonces_for_graph(
            &self,
            instance_id: Uuid,
            graph_id: Uuid,
        ) -> [(SecNonce, PubNonce, Signature); COMMITTEE_PRE_SIGN_NUM] {
            let domain = vec![
                b"committee_bitvm_nonces".to_vec(),
                instance_id.as_bytes().to_vec(),
                graph_id.as_bytes().to_vec(),
            ]
            .concat();
            let nonce_seed = derive_secret(&self.0, &domain);
            let signer_keypair = self.keypair_for_instance(instance_id);
            generate_nonce_from_seed(nonce_seed, graph_id.as_u128() as usize, signer_keypair)
        }
    }

    pub struct OperatorMasterKey(Keypair);
    impl OperatorMasterKey {
        pub fn new(inner: Keypair) -> Self {
            OperatorMasterKey(inner)
        }
        pub fn master_keypair(&self) -> Keypair {
            self.0
        }
        pub fn keypair_for_graph(&self, _graph_id: Uuid) -> Keypair {
            self.master_keypair()
        }
        pub fn wots_keypair_for_graph(&self, graph_id: Uuid) -> (WotsSecretKeys, WotsPublicKeys) {
            let domain =
                vec![b"operator_bitvm_wots_key".to_vec(), graph_id.as_bytes().to_vec()].concat();
            let wot_seed = derive_secret(&self.0, &domain);
            generate_wots_keys(&wot_seed)
        }
    }
}

#[allow(unused_variables, dead_code)]
pub mod todo_funcs {
    use super::*;
    use bitcoin::{Address, Transaction};
    use bitvm::treepp::*;
    use goat::scripts::generate_burn_script_address;
    use goat::transactions::base::Input;
    use std::str::FromStr;

    pub fn get_bitvm_key() -> Result<Keypair, Box<dyn std::error::Error>> {
        let bitvm_secret = std::env::var("BITVM_SECRET").expect("BITVM_SECRET is missing");
        Ok(Keypair::from_seckey_str_global(&bitvm_secret)?)
    }

    /// Returns the number of committee members
    /// Require to reach consensus.
    pub fn committee_member_num() -> usize {
        3
    }

    /// Determines whether the operator should participate in generating a new graph.
    ///
    /// Conditions:
    /// - Participation should be attempted as often as possible.
    /// - Only one graph can be generated at a time; generation must be sequential, not parallel.
    /// - If the remaining funds are less than the required stake-amount, operator should not participate.
    pub fn should_generate_graph(create_graph_prepare_data: &CreateGraphPrepare) -> bool {
        true
    }

    /// Checks whether the given graph belongs to the current operator node.
    ///
    /// Require to store which graphs were generated by current operator node
    pub fn is_my_graph(instance_id: Uuid, graph_id: Uuid) -> bool {
        true
    }

    /// Database related
    pub fn store_committee_pubkeys(
        instance_id: Uuid,
        pubkey: PublicKey,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
    pub fn get_committee_pubkeys(
        instance_id: Uuid,
    ) -> Result<Vec<PublicKey>, Box<dyn std::error::Error>> {
        Ok(vec![])
    }
    pub fn store_committee_pub_nonces(
        instance_id: Uuid,
        graph_id: Uuid,
        committee_pubkey: PublicKey,
        pub_nonces: [PubNonce; COMMITTEE_PRE_SIGN_NUM],
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
    pub fn get_committee_pub_nonces(
        instance_id: Uuid,
        graph_id: Uuid,
    ) -> Result<Vec<[PubNonce; COMMITTEE_PRE_SIGN_NUM]>, Box<dyn std::error::Error>> {
        Ok(vec![])
    }
    pub fn store_committee_partial_sigs(
        instance_id: Uuid,
        graph_id: Uuid,
        committee_pubkey: PublicKey,
        partial_sigs: [PartialSignature; COMMITTEE_PRE_SIGN_NUM],
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
    pub fn get_committee_partial_sigs(
        instance_id: Uuid,
        graph_id: Uuid,
    ) -> Result<Vec<[PartialSignature; COMMITTEE_PRE_SIGN_NUM]>, Box<dyn std::error::Error>> {
        Ok(vec![])
    }
    pub fn store_graph(
        instance_id: Uuid,
        graph_id: Uuid,
        graph: &Bitvm2Graph,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
    pub fn update_graph(
        instance_id: Uuid,
        graph_id: Uuid,
        graph: &Bitvm2Graph,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
    pub fn get_graph(
        instance_id: Uuid,
        graph_id: Uuid,
    ) -> Result<Bitvm2Graph, Box<dyn std::error::Error>> {
        Err("TODO".into())
    }
    /// Returns a list of all graph IDs and their corresponding instance IDs
    /// that were generated by the given operator public key.
    ///
    /// Two possible ways:
    /// - store in database
    /// - in-memory data during the pegin phase, and queried from the L2 contract during the pegout phase
    pub fn get_graph_ids_by_operator_pubkey(
        operator_pubkey: PublicKey,
    ) -> Result<Vec<(Uuid, Uuid)>, Box<dyn std::error::Error>> {
        Ok(vec![])
    }

    /// Checks whether the status of the graph (identified by instance ID and graph ID)
    /// on the Layer 2 contract is currently `Initialized`.
    pub fn is_withdraw_initialized_on_l2(instance_id: Uuid, graph_id: Uuid) -> bool {
        true
    }

    /// Checks whether the timelock for the specified kickoff transaction has expired,
    /// indicating that the `take1` transaction can now be sent.
    ///
    /// The timelock duration is a fixed constant (goat::constants::CONNECTOR_3_TIMELOCK)
    pub fn is_take1_timelock_expired(kickoff_txid: Txid) -> bool {
        true
    }

    /// Checks whether the timelock for the specified assert-final transaction has expired,
    /// allowing the `take2` transaction to proceed.
    ///
    /// The timelock duration is a fixed constant (goat::constants::CONNECTOR_4_TIMELOCK)
    pub fn is_take2_timelock_expired(assert_final_txid: Txid) -> bool {
        true
    }

    /// Calculates the required stake amount for the operator.
    ///
    /// Formula:
    /// stake_amount = fixed_min_stake_amount + (pegin_amount * stake_rate)
    pub fn get_stake_amount() -> Amount {
        Amount::from_sat(20000000)
    }

    /// Calculates the required challenge amount, which is based on the stake amount.
    ///
    /// Formula:
    /// challenge_amount = stake_amount * challenge_rate
    pub fn get_challenge_amount() -> Amount {
        Amount::from_sat(20000000)
    }

    /// Selects suitable UTXOs from the operator’s available funds to construct inputs
    /// for the pre-kickoff transaction.
    ///
    /// Notes:
    /// - UTXOs must be sent to a dedicated P2WSH address, generated at node startup from operator-pubkey
    /// - The same P2WSH address is also used for change output.
    pub fn select_operator_inputs(stake_amount: Amount) -> CustomInputs {
        let mock_input = Input {
            outpoint: OutPoint {
                txid: Txid::from_str(
                    "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
                )
                .unwrap(),
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

    /// Loads partial scripts from a local file.
    ///
    /// These scripts should be fetched from IPFS during node startup and saved to disk.
    pub fn get_partial_scripts() -> Vec<Script> {
        vec![]
    }

    /// Broadcasts a raw transaction to the Bitcoin network using the mempool API.
    ///
    /// Requirements:
    /// - The mempool API URL must be configured.
    /// - The transaction should already be fully signed.
    pub fn broadcast_tx(tx: Transaction) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    /// Signs and broadcasts pre-kickoff transaction.
    ///
    /// The transaction must be signed using the operator's private key
    /// before broadcasting it to the network.
    pub fn sign_and_broadcast_prekickoff_tx(
        tx: Transaction,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    /// Completes and broadcasts a challenge transaction.
    ///
    /// This involves:
    /// - Selecting UTXOs with sufficient amount (may include change),
    /// - Signing the transaction,
    /// - Broadcasting it to the network.
    ///
    /// Notes:
    /// - The challenge node must have pre-funded a P2WSH address during startup.
    pub fn complete_and_broadcast_challenge_tx(
        challenge_tx: Transaction,
    ) -> Result<Txid, Box<dyn std::error::Error>> {
        Ok(Txid::from_str("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d")?)
    }

    /// Returns the address to receive disprove reward, which is a P2WSH address
    /// generated by the challenge node at startup.
    pub fn disprove_reward_address() -> Result<Address, Box<dyn std::error::Error>> {
        Err("TODO".into())
    }

    /// Validates the kickoff transaction for a specific graph.
    ///
    /// A kickoff transaction is considered invalid if:
    /// - It has already been broadcast on Layer 1,
    /// - But the corresponding graph status on Layer 2 is not `Initialized`.
    pub fn validate_kickoff(
        instance_id: Uuid,
        graph_id: Uuid,
        kickoff_txid: Txid,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(true)
    }

    /// Validates whether the given challenge transaction has been confirmed on Layer 1.
    pub fn validate_challenge(challenge_txid: Txid) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(true)
    }

    /// Retrieves the Groth16 proof, public inputs, and verifying key
    /// for the given graph.
    ///
    /// These are fetched via the ProofNetwork SDK.
    pub fn get_groth16_proof(
        instance_id: Uuid,
        graph_id: Uuid,
    ) -> Result<(Groth16Proof, PublicInputs, VerifyingKey), Box<dyn std::error::Error>> {
        Err("TODO".into())
    }

    /// Validates the provided assert-commit transactions.
    ///
    /// Steps:
    /// - Extract the Groth16 proof from the witness fields of the provided transactions,
    /// - Verify the validity of the proof.
    ///
    /// Returns:
    /// - `Ok(None)` if the assert is valid,
    /// - `Ok(Some((index, disprove_script)))` if invalid, providing the witness info for later disprove.
    pub fn validate_assert(
        assert_commit_txns: [Txid; COMMIT_TX_NUM],
    ) -> Result<Option<(usize, Script)>, Box<dyn std::error::Error>> {
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
    // TODO: Actor::All
    if message.actor != actor {
        return Ok(());
    }
    println!("Handle message: {:?}", message);
    let content: GOATMessageContent = message.to_typed()?;
    match (content, actor) {
        (GOATMessageContent::CreateInstance(receive_data), Actor::Committee) => {
            let instance_id = receive_data.instance_id;
            let master_key =
                bitvm_key_derivation::CommitteeMasterKey::new(todo_funcs::get_bitvm_key()?);
            let keypair = master_key.keypair_for_instance(instance_id);
            let message_content = GOATMessageContent::CreateGraphPrepare(CreateGraphPrepare {
                instance_id,
                network: receive_data.network,
                pegin_amount: receive_data.pegin_amount,
                depositor_evm_address: receive_data.depositor_evm_address,
                user_inputs: receive_data.user_inputs,
                committee_member_pubkey: keypair.public_key().into(),
                committee_members_num: todo_funcs::committee_member_num(),
            });
            todo_funcs::store_committee_pubkeys(
                receive_data.instance_id,
                keypair.public_key().into(),
            )?;
            send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
            send_to_peer(swarm, GOATMessage::from_typed(Actor::Operator, &message_content)?)?;
        }
        (GOATMessageContent::CreateGraphPrepare(receive_data), Actor::Operator) => {
            todo_funcs::store_committee_pubkeys(
                receive_data.instance_id,
                receive_data.committee_member_pubkey,
            )?;
            let collected_keys = todo_funcs::get_committee_pubkeys(receive_data.instance_id)?;
            if todo_funcs::should_generate_graph(&receive_data)
                && collected_keys.len() == receive_data.committee_members_num
            {
                let graph_id = Uuid::new_v4();
                let master_key =
                    bitvm_key_derivation::OperatorMasterKey::new(todo_funcs::get_bitvm_key()?);
                let keypair = master_key.keypair_for_graph(graph_id);
                let (_, operator_wots_pubkeys) = master_key.wots_keypair_for_graph(graph_id);
                let committee_agg_pubkey = key_aggregation(&collected_keys);
                let disprove_scripts = generate_disprove_scripts(
                    &todo_funcs::get_partial_scripts(),
                    &operator_wots_pubkeys,
                );
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
                    operator_inputs: todo_funcs::select_operator_inputs(
                        todo_funcs::get_stake_amount(),
                    ),
                };
                let disprove_scripts_bytes =
                    disprove_scripts.iter().map(|x| x.clone().compile().into_bytes()).collect();
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
        }
        (GOATMessageContent::CreateGraph(receive_data), Actor::Committee) => {
            todo_funcs::store_graph(
                receive_data.instance_id,
                receive_data.graph_id,
                &receive_data.graph,
            )?;
            let master_key =
                bitvm_key_derivation::CommitteeMasterKey::new(todo_funcs::get_bitvm_key()?);
            let nonces =
                master_key.nonces_for_graph(receive_data.instance_id, receive_data.graph_id);
            let keypair = master_key.keypair_for_instance(receive_data.instance_id);
            let pub_nonces: [PubNonce; COMMITTEE_PRE_SIGN_NUM] =
                std::array::from_fn(|i| nonces[i].1.clone());
            let message_content = GOATMessageContent::NonceGeneration(NonceGeneration {
                instance_id: receive_data.instance_id,
                graph_id: receive_data.graph_id,
                committee_pubkey: keypair.public_key().into(),
                pub_nonces,
                committee_members_num: receive_data.graph.parameters.committee_pubkeys.len(),
            });
            send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
        }
        (GOATMessageContent::NonceGeneration(receive_data), Actor::Committee) => {
            todo_funcs::store_committee_pub_nonces(
                receive_data.instance_id,
                receive_data.graph_id,
                receive_data.committee_pubkey,
                receive_data.pub_nonces,
            )?;
            let graph = todo_funcs::get_graph(receive_data.instance_id, receive_data.graph_id)?;
            let master_key =
                bitvm_key_derivation::CommitteeMasterKey::new(todo_funcs::get_bitvm_key()?);
            let keypair = master_key.keypair_for_instance(receive_data.instance_id);
            let nonces =
                master_key.nonces_for_graph(receive_data.instance_id, receive_data.graph_id);
            let sec_nonces: [SecNonce; COMMITTEE_PRE_SIGN_NUM] =
                std::array::from_fn(|i| nonces[i].0.clone());
            let collected_pub_nonces = todo_funcs::get_committee_pub_nonces(
                receive_data.instance_id,
                receive_data.graph_id,
            )?;
            if collected_pub_nonces.len() == receive_data.committee_members_num {
                let agg_nonces = nonces_aggregation(collected_pub_nonces);
                let committee_partial_sigs =
                    committee_pre_sign(keypair, sec_nonces, agg_nonces.clone(), &graph)?;
                let message_content = GOATMessageContent::CommitteePresign(CommitteePresign {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    committee_pubkey: receive_data.committee_pubkey,
                    committee_partial_sigs,
                    agg_nonces,
                    committee_members_num: receive_data.committee_members_num,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
            };
        }
        (GOATMessageContent::CommitteePresign(receive_data), Actor::Operator) => {
            if todo_funcs::is_my_graph(receive_data.instance_id, receive_data.graph_id) {
                todo_funcs::store_committee_partial_sigs(
                    receive_data.instance_id,
                    receive_data.graph_id,
                    receive_data.committee_pubkey,
                    receive_data.committee_partial_sigs,
                )?;
                let collected_partial_sigs = todo_funcs::get_committee_partial_sigs(
                    receive_data.instance_id,
                    receive_data.graph_id,
                )?;
                if collected_partial_sigs.len() == receive_data.committee_members_num {
                    let mut grouped_partial_sigs: [Vec<PartialSignature>; COMMITTEE_PRE_SIGN_NUM] =
                        Default::default();
                    for partial_sigs in collected_partial_sigs {
                        for (i, sig) in partial_sigs.into_iter().enumerate() {
                            grouped_partial_sigs[i].push(sig);
                        }
                    }
                    let mut graph =
                        todo_funcs::get_graph(receive_data.instance_id, receive_data.graph_id)?;
                    signature_aggregation_and_push(
                        &grouped_partial_sigs,
                        &receive_data.agg_nonces,
                        &mut graph,
                    )?;
                    todo_funcs::update_graph(
                        receive_data.instance_id,
                        receive_data.graph_id,
                        &graph,
                    )?;
                    let prekickoff_tx = graph.pre_kickoff.tx().clone();
                    todo_funcs::sign_and_broadcast_prekickoff_tx(prekickoff_tx)?;
                    let message_content = GOATMessageContent::GraphFinalize(GraphFinalize {
                        instance_id: receive_data.instance_id,
                        graph_id: receive_data.graph_id,
                        graph,
                    });
                    send_to_peer(
                        swarm,
                        GOATMessage::from_typed(Actor::Committee, &message_content)?,
                    )?;
                    send_to_peer(
                        swarm,
                        GOATMessage::from_typed(Actor::Challenger, &message_content)?,
                    )?;
                }
            };
        }
        (GOATMessageContent::GraphFinalize(receive_data), _) => {
            todo_funcs::store_graph(
                receive_data.instance_id,
                receive_data.graph_id,
                &receive_data.graph,
            )?;
        }

        // peg-out
        // KickoffReady sent by relayer
        (GOATMessageContent::KickoffReady(receive_data), Actor::Operator) => {
            if todo_funcs::is_my_graph(receive_data.instance_id, receive_data.graph_id)
                && todo_funcs::is_withdraw_initialized_on_l2(
                    receive_data.instance_id,
                    receive_data.graph_id,
                )
            {
                let mut graph =
                    todo_funcs::get_graph(receive_data.instance_id, receive_data.graph_id)?;
                let master_key =
                    bitvm_key_derivation::OperatorMasterKey::new(todo_funcs::get_bitvm_key()?);
                let keypair = master_key.keypair_for_graph(receive_data.graph_id);
                let (operator_wots_seckeys, operator_wots_pubkeys) =
                    master_key.wots_keypair_for_graph(receive_data.graph_id);
                let mut kickoff_commit_data = [0u8; 32];
                kickoff_commit_data[..16].copy_from_slice(receive_data.instance_id.as_bytes());
                kickoff_commit_data[16..].copy_from_slice(receive_data.graph_id.as_bytes());
                let kickoff_tx = operator_sign_kickoff(
                    keypair,
                    &mut graph,
                    &operator_wots_seckeys,
                    &operator_wots_pubkeys,
                    kickoff_commit_data,
                )?;
                let kickoff_txid = kickoff_tx.compute_txid();
                todo_funcs::broadcast_tx(kickoff_tx)?;
                let message_content = GOATMessageContent::KickoffSent(KickoffSent {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    kickoff_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Challenger, &message_content)?)?;
            }
        }
        // Take1Ready sent by relayer
        (GOATMessageContent::Take1Ready(receive_data), Actor::Operator) => {
            if todo_funcs::is_my_graph(receive_data.instance_id, receive_data.graph_id) {
                let mut graph =
                    todo_funcs::get_graph(receive_data.instance_id, receive_data.graph_id)?;
                if todo_funcs::is_take1_timelock_expired(graph.take1.tx().compute_txid()) {
                    let master_key =
                        bitvm_key_derivation::OperatorMasterKey::new(todo_funcs::get_bitvm_key()?);
                    let keypair = master_key.keypair_for_graph(receive_data.graph_id);
                    let take1_tx = operator_sign_take1(keypair, &mut graph)?;
                    let take1_txid = take1_tx.compute_txid();
                    todo_funcs::broadcast_tx(take1_tx)?;
                    let message_content = GOATMessageContent::Take1Sent(Take1Sent {
                        instance_id: receive_data.instance_id,
                        graph_id: receive_data.graph_id,
                        take1_txid,
                    });
                    send_to_peer(
                        swarm,
                        GOATMessage::from_typed(Actor::Committee, &message_content)?,
                    )?;
                }
            }
        }
        (GOATMessageContent::KickoffSent(receive_data), Actor::Challenger) => {
            if !todo_funcs::validate_kickoff(
                receive_data.instance_id,
                receive_data.graph_id,
                receive_data.kickoff_txid,
            )? {
                let mut graph =
                    todo_funcs::get_graph(receive_data.instance_id, receive_data.graph_id)?;
                let challenge_tx = export_challenge_tx(&mut graph)?;
                let challenge_txid = todo_funcs::complete_and_broadcast_challenge_tx(challenge_tx)?;
                let message_content = GOATMessageContent::ChallengeSent(ChallengeSent {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    challenge_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Operator, &message_content)?)?;
            }
        }
        (GOATMessageContent::ChallengeSent(receive_data), Actor::Operator) => {
            if todo_funcs::is_my_graph(receive_data.instance_id, receive_data.graph_id)
                && todo_funcs::validate_challenge(receive_data.challenge_txid)?
            {
                let mut graph =
                    todo_funcs::get_graph(receive_data.instance_id, receive_data.graph_id)?;
                let master_key =
                    bitvm_key_derivation::OperatorMasterKey::new(todo_funcs::get_bitvm_key()?);
                let keypair = master_key.keypair_for_graph(receive_data.graph_id);
                let (operator_wots_seckeys, operator_wots_pubkeys) =
                    master_key.wots_keypair_for_graph(receive_data.graph_id);
                let (proof, pubin, vk) =
                    todo_funcs::get_groth16_proof(receive_data.instance_id, receive_data.graph_id)?;
                let proof_sigs = sign_proof(&vk, proof, pubin, &operator_wots_seckeys);
                let (assert_init_tx, assert_commit_txns, assert_final_tx) =
                    operator_sign_assert(keypair, &mut graph, &operator_wots_pubkeys, proof_sigs)?;
                let assert_init_txid = assert_init_tx.compute_txid();
                todo_funcs::broadcast_tx(assert_init_tx)?;
                let mut assert_commit_txids = Vec::with_capacity(COMMIT_TX_NUM);
                for tx in assert_commit_txns {
                    assert_commit_txids.push(tx.compute_txid());
                    todo_funcs::broadcast_tx(tx)?;
                }
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
        }
        // Take2Ready sent by relayer
        (GOATMessageContent::Take2Ready(receive_data), Actor::Operator) => {
            if todo_funcs::is_my_graph(receive_data.instance_id, receive_data.graph_id) {
                // checkout timelock
                let mut graph =
                    todo_funcs::get_graph(receive_data.instance_id, receive_data.graph_id)?;
                if todo_funcs::is_take2_timelock_expired(graph.assert_final.tx().compute_txid()) {
                    let master_key =
                        bitvm_key_derivation::OperatorMasterKey::new(todo_funcs::get_bitvm_key()?);
                    let keypair = master_key.keypair_for_graph(receive_data.graph_id);
                    let take2_tx = operator_sign_take2(keypair, &mut graph)?;
                    let take2_txid = take2_tx.compute_txid();
                    todo_funcs::broadcast_tx(take2_tx)?;
                    let message_content = GOATMessageContent::Take2Sent(Take2Sent {
                        instance_id: receive_data.instance_id,
                        graph_id: receive_data.graph_id,
                        take2_txid,
                    });
                    send_to_peer(
                        swarm,
                        GOATMessage::from_typed(Actor::Committee, &message_content)?,
                    )?;
                }
            }
        }
        (GOATMessageContent::AssertSent(receive_data), Actor::Challenger) => {
            if let Some(disprove_witness) =
                todo_funcs::validate_assert(receive_data.assert_commit_txids)?
            {
                let mut graph =
                    todo_funcs::get_graph(receive_data.instance_id, receive_data.graph_id)?;
                let disprove_scripts = generate_disprove_scripts(
                    &todo_funcs::get_partial_scripts(),
                    &graph.parameters.operator_wots_pubkeys,
                );
                let disprove_scripts_bytes =
                    disprove_scripts.iter().map(|x| x.clone().compile().into_bytes()).collect();
                let assert_wots_pubkeys = graph.parameters.operator_wots_pubkeys.1.clone();
                let disprove_tx = sign_disprove(
                    &mut graph,
                    disprove_witness,
                    disprove_scripts_bytes,
                    &assert_wots_pubkeys,
                    todo_funcs::disprove_reward_address()?,
                )?;
                let disprove_txid = disprove_tx.compute_txid();
                todo_funcs::broadcast_tx(disprove_tx)?;
                let message_content = GOATMessageContent::DisproveSent(DisproveSent {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    disprove_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
            }
        }
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
