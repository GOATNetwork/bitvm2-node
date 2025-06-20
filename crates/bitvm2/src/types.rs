use crate::committee::{COMMITTEE_PRE_SIGN_NUM, push_committee_pre_signatures};
use crate::operator::push_operator_pre_signature;
use anyhow::Result;
use bitcoin::{Address, Amount, Network, PrivateKey, PublicKey, XOnlyPublicKey, key::Keypair};
use bitcoin::{OutPoint, TapNodeHash, Witness};
use bitvm::chunk::api::{
    NUM_HASH, NUM_PUBS, NUM_U256, PublicKeys as ApiWotsPublicKeys, Signatures as ApiWotsSignatures,
};
use bitvm::signatures::signing_winternitz::{WinternitzPublicKey, WinternitzSecret};
use goat::commitments::{CommitmentMessageId, NUM_KICKOFF};
use goat::connectors::connector_0::Connector0;
use goat::connectors::connector_3::Connector3;
use goat::connectors::connector_6::Connector6;
use goat::connectors::connector_a::ConnectorA;
use goat::connectors::connector_b::ConnectorB;
use goat::connectors::connector_d::ConnectorD;
use goat::contexts::base::BaseContext;
use goat::contexts::operator::OperatorContext;
use goat::contexts::verifier::VerifierContext;
use goat::transactions::assert::utils::{AllCommitConnectorsE, AssertCommitConnectorsF};
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::{
    assert::assert_commit::AssertCommitTransactionSet,
    assert::assert_final::AssertFinalTransaction, assert::assert_initial::AssertInitialTransaction,
    base::Input, challenge::ChallengeTransaction, disprove::DisproveTransaction,
    kick_off::KickOffTransaction, peg_in::peg_in::PegInTransaction,
    peg_out_confirm::PreKickoffTransaction, take_1::Take1Transaction, take_2::Take2Transaction,
};
use rand::{Rng, distributions::Alphanumeric};
use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};

pub type VerifyingKey = ark_groth16::VerifyingKey<ark_bn254::Bn254>;
pub type Groth16Proof = ark_groth16::Proof<ark_bn254::Bn254>;
pub type PublicInputs = Vec<ark_bn254::Fr>;

pub type Groth16WotsSignatures = ApiWotsSignatures;

const NUM_SIGS: usize = NUM_PUBS + NUM_HASH + NUM_U256;
pub type KickoffWotsSecretKeys = Box<[WinternitzSecret; NUM_KICKOFF]>;
pub type Groth16WotsSecretKeys = Box<[String; NUM_SIGS]>;
pub type WotsSecretKeys = (KickoffWotsSecretKeys, Groth16WotsSecretKeys);

pub type Groth16WotsPublicKeys = Box<ApiWotsPublicKeys>;
pub type KickoffWotsPublicKeys = Box<[WinternitzPublicKey; NUM_KICKOFF]>;
pub type WotsPublicKeys = (KickoffWotsPublicKeys, Groth16WotsPublicKeys);

pub fn random_string(len: usize) -> String {
    rand::thread_rng().sample_iter(&Alphanumeric).take(len).map(char::from).collect()
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Bitvm2Parameters {
    pub network: Network,
    pub depositor_evm_address: [u8; 20],
    pub pegin_amount: Amount,
    pub stake_amount: Amount,
    pub challenge_amount: Amount,
    pub committee_pubkeys: Vec<PublicKey>,
    pub committee_agg_pubkey: PublicKey,
    pub operator_pubkey: PublicKey,
    #[serde(with = "node_serializer::wots_pubkeys")]
    pub operator_wots_pubkeys: WotsPublicKeys,
    pub user_inputs: CustomInputs,
    pub operator_inputs: CustomInputs,
}

impl Bitvm2Parameters {
    pub fn get_verifier_context(&self, committee_member_keypair: Keypair) -> VerifierContext {
        let network = self.network;
        let committee_public_key = self.committee_agg_pubkey;
        let committee_taproot_public_key = XOnlyPublicKey::from(committee_public_key);
        let private_key = PrivateKey::new(committee_member_keypair.secret_key(), network);
        let committee_member_public_key = PublicKey::from_private_key(SECP256K1, &private_key);
        VerifierContext {
            network,
            verifier_keypair: committee_member_keypair,
            verifier_public_key: committee_member_public_key,
            n_of_n_public_keys: self.committee_pubkeys.clone(),
            n_of_n_public_key: committee_public_key,
            n_of_n_taproot_public_key: committee_taproot_public_key,
        }
    }

    pub fn get_operator_context(&self, operator_keypair: Keypair) -> OperatorContext {
        let network = self.network;
        let operator_public_key = self.operator_pubkey;
        let operator_taproot_public_key = XOnlyPublicKey::from(operator_public_key);
        let committee_public_key = self.committee_agg_pubkey;
        let committee_taproot_public_key = XOnlyPublicKey::from(committee_public_key);
        OperatorContext {
            network,
            operator_keypair,
            operator_public_key,
            operator_taproot_public_key,

            n_of_n_public_keys: self.committee_pubkeys.clone(),
            n_of_n_public_key: committee_public_key,
            n_of_n_taproot_public_key: committee_taproot_public_key,
        }
    }

    pub fn get_base_context(&self) -> BaseBitvmContext {
        let network = self.network;
        let n_of_n_public_keys = self.committee_pubkeys.clone();
        let n_of_n_public_key = self.committee_agg_pubkey;
        let n_of_n_taproot_public_key = XOnlyPublicKey::from(n_of_n_public_key);
        BaseBitvmContext {
            network,
            n_of_n_public_keys,
            n_of_n_public_key,
            n_of_n_taproot_public_key,
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Bitvm2Graph {
    pub(crate) operator_pre_signed: bool,
    pub(crate) committee_pre_signed: bool,
    pub parameters: Bitvm2Parameters,
    pub connector_c_taproot_merkle_root: TapNodeHash,
    pub pegin: PegInTransaction,
    pub pre_kickoff: PreKickoffTransaction,
    pub kickoff: KickOffTransaction,
    pub take1: Take1Transaction,
    pub challenge: ChallengeTransaction,
    pub assert_init: AssertInitialTransaction,
    pub assert_commit: AssertCommitTransactionSet,
    pub assert_final: AssertFinalTransaction,
    pub take2: Take2Transaction,
    pub disprove: DisproveTransaction,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SimplifiedBitvm2Graph {
    pub parameters: Bitvm2Parameters,
    pub operator_pre_sigs: Option<Witness>,
    pub committee_pre_sigs: Option<[Witness; COMMITTEE_PRE_SIGN_NUM]>,
    pub connector_c_taproot_merkle_root: TapNodeHash,
    pub assert_final: AssertFinalTransaction,
    pub take2: Take2Transaction,
    pub disprove: DisproveTransaction,
}

impl Bitvm2Graph {
    pub fn operator_pre_signed(&self) -> bool {
        self.operator_pre_signed
    }
    pub fn committee_pre_signed(&self) -> bool {
        self.committee_pre_signed
    }
    pub fn from_simplified(simplified_graph: SimplifiedBitvm2Graph) -> Result<Self> {
        let SimplifiedBitvm2Graph {
            parameters,
            operator_pre_sigs,
            committee_pre_sigs,
            connector_c_taproot_merkle_root,
            assert_final,
            take2,
            disprove,
        } = simplified_graph;

        let user_inputs = parameters.user_inputs.clone();
        let operator_inputs = parameters.operator_inputs.clone();

        // Pegin
        let network = parameters.network;
        let committee_taproot_pubkey = XOnlyPublicKey::from(parameters.committee_agg_pubkey);
        let connector_0 = Connector0::new(network, &committee_taproot_pubkey);
        let pegin_message =
            [get_magic_bytes(&network), parameters.depositor_evm_address.to_vec()].concat();
        let pegin = PegInTransaction::new_for_validation(
            &connector_0,
            user_inputs.inputs,
            user_inputs.input_amount,
            user_inputs.fee_amount,
            user_inputs.change_address,
            pegin_message,
        );
        let pegin_txid = pegin.tx().compute_txid();

        // Pre-Kickoff
        let operator_pubkey = parameters.operator_pubkey;
        let operator_taproot_pubkey = XOnlyPublicKey::from(operator_pubkey);
        let kickoff_wots_commitment_keys =
            CommitmentMessageId::pubkey_map_for_kickoff(&parameters.operator_wots_pubkeys.0);
        let connector_6 =
            Connector6::new(network, &operator_taproot_pubkey, &kickoff_wots_commitment_keys);
        let pre_kickoff = PreKickoffTransaction::new_unsigned(
            &connector_6,
            operator_inputs.inputs,
            operator_inputs.input_amount,
            operator_inputs.fee_amount,
            operator_inputs.change_address,
        );
        let pre_kickoff_txid = pre_kickoff.tx().compute_txid();

        // Kickoff
        let connector_3 = Connector3::new(network, &operator_pubkey);
        let connector_a =
            ConnectorA::new(network, &operator_taproot_pubkey, &committee_taproot_pubkey);
        let connector_b = ConnectorB::new(network, &operator_taproot_pubkey);
        let kickoff_input_0_vout: usize = 0;
        let kickoff_input_0 = Input {
            outpoint: OutPoint { txid: pre_kickoff_txid, vout: kickoff_input_0_vout as u32 },
            amount: pre_kickoff.tx().output[kickoff_input_0_vout].value,
        };
        let kickoff = KickOffTransaction::new_for_validation(
            &connector_3,
            &connector_6,
            &connector_a,
            &connector_b,
            kickoff_input_0,
        );
        let kickoff_txid = kickoff.tx().compute_txid();

        // take-1
        let take1_input_0_vout: usize = 0;
        let take1_input_0 = Input {
            outpoint: OutPoint { txid: pegin_txid, vout: take1_input_0_vout as u32 },
            amount: pegin.tx().output[take1_input_0_vout].value,
        };
        let take1_input_1_vout: usize = 1;
        let take1_input_1 = Input {
            outpoint: OutPoint { txid: kickoff_txid, vout: take1_input_1_vout as u32 },
            amount: kickoff.tx().output[take1_input_1_vout].value,
        };
        let take1_input_2_vout: usize = 0;
        let take1_input_2 = Input {
            outpoint: OutPoint { txid: kickoff_txid, vout: take1_input_2_vout as u32 },
            amount: kickoff.tx().output[take1_input_2_vout].value,
        };
        let take1_input_3_vout: usize = 2;
        let take1_input_3 = Input {
            outpoint: OutPoint { txid: kickoff_txid, vout: take1_input_3_vout as u32 },
            amount: kickoff.tx().output[take1_input_3_vout].value,
        };
        let take1 = Take1Transaction::new_for_validation(
            network,
            &operator_pubkey,
            &connector_0,
            &connector_3,
            &connector_a,
            &connector_b,
            take1_input_0,
            take1_input_1,
            take1_input_2,
            take1_input_3,
        );

        // challenge
        let challenge_input_0_vout: usize = 1;
        let challenge_input_0 = Input {
            outpoint: OutPoint { txid: kickoff_txid, vout: challenge_input_0_vout as u32 },
            amount: kickoff.tx().output[challenge_input_0_vout].value,
        };
        let challenge = ChallengeTransaction::new_for_validation(
            network,
            &operator_pubkey,
            &connector_a,
            challenge_input_0,
            parameters.challenge_amount,
        );

        // assert-initial
        let assert_wots_pubkeys = &parameters.operator_wots_pubkeys.1;
        let connector_d = ConnectorD::new(network, &committee_taproot_pubkey);
        let all_assert_commit_connectors_e =
            AllCommitConnectorsE::new(network, &operator_pubkey, assert_wots_pubkeys);
        let assert_init_input_0_vout: usize = 2;
        let assert_init_input_0 = Input {
            outpoint: OutPoint { txid: kickoff_txid, vout: assert_init_input_0_vout as u32 },
            amount: kickoff.tx().output[assert_init_input_0_vout].value,
        };
        let assert_init = AssertInitialTransaction::new_for_validation(
            &connector_b,
            &connector_d,
            &all_assert_commit_connectors_e,
            assert_init_input_0,
        );
        let assert_init_txid = assert_init.tx().compute_txid();

        // assert-commit
        let connectors_f = AssertCommitConnectorsF::new(network, &operator_pubkey);
        let vout_base: usize = 1;
        let assert_commit_inputs = (0..all_assert_commit_connectors_e.connectors_num())
            .map(|idx| Input {
                outpoint: OutPoint { txid: assert_init_txid, vout: (idx + vout_base) as u32 },
                amount: assert_init.tx().output[idx + vout_base].value,
            })
            .collect();
        let assert_commit = AssertCommitTransactionSet::new(
            &all_assert_commit_connectors_e,
            &connectors_f,
            assert_commit_inputs,
        );

        let mut graph = Bitvm2Graph {
            operator_pre_signed: false,
            committee_pre_signed: false,
            parameters,
            connector_c_taproot_merkle_root,
            pegin,
            pre_kickoff,
            kickoff,
            take1,
            challenge,
            assert_init,
            assert_commit,
            assert_final,
            take2,
            disprove,
        };
        if let Some(signed_witness) = operator_pre_sigs {
            push_operator_pre_signature(&mut graph, &signed_witness)?
        };
        if let Some(signed_witness) = committee_pre_sigs {
            push_committee_pre_signatures(&mut graph, &signed_witness)?
        };
        Ok(graph)
    }
    pub fn to_simplified(&self) -> SimplifiedBitvm2Graph {
        let operator_pre_sigs = if self.operator_pre_signed {
            Some(self.challenge.tx().input[0].witness.clone())
        } else {
            None
        };
        let committee_pre_sigs = if self.committee_pre_signed {
            Some([
                self.take1.tx().input[0].witness.clone(),
                self.take2.tx().input[0].witness.clone(),
                self.take2.tx().input[2].witness.clone(),
                self.assert_final.tx().input[0].witness.clone(),
                self.disprove.tx().input[0].witness.clone(),
            ])
        } else {
            None
        };
        SimplifiedBitvm2Graph {
            parameters: self.parameters.clone(),
            operator_pre_sigs,
            committee_pre_sigs,
            connector_c_taproot_merkle_root: self.connector_c_taproot_merkle_root,
            assert_final: self.assert_final.clone(),
            take2: self.take2.clone(),
            disprove: self.disprove.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct CustomInputs {
    pub inputs: Vec<Input>,
    /// stake amount / pegin_amount
    pub input_amount: Amount,
    pub fee_amount: Amount,
    #[serde(with = "node_serializer::address")]
    pub change_address: Address,
}

impl CustomInputs {
    pub fn validate_amount(&self) -> bool {
        let res = self.inputs.iter().fold(Amount::ZERO, |acc, v| acc + v.amount);
        res >= self.input_amount + self.fee_amount
    }
}

pub type Error = String;

pub struct BaseBitvmContext {
    pub network: Network,
    pub n_of_n_public_keys: Vec<PublicKey>,
    pub n_of_n_public_key: PublicKey,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
}

impl BaseContext for BaseBitvmContext {
    fn network(&self) -> Network {
        self.network
    }
    fn n_of_n_public_keys(&self) -> &Vec<PublicKey> {
        &self.n_of_n_public_keys
    }
    fn n_of_n_public_key(&self) -> &PublicKey {
        &self.n_of_n_public_key
    }
    fn n_of_n_taproot_public_key(&self) -> &XOnlyPublicKey {
        &self.n_of_n_taproot_public_key
    }
}

pub fn get_magic_bytes(net: &Network) -> Vec<u8> {
    match net {
        Network::Bitcoin => hex::encode(b"GTV6").as_bytes().to_vec(),
        _ => hex::encode(b"GTT6").as_bytes().to_vec(),
    }
}

pub mod node_serializer {
    use serde::{self, Deserialize, Deserializer, Serializer, ser::Error};
    use std::str::FromStr;

    pub mod address {
        use super::*;
        use bitcoin::Address;

        pub fn serialize<S>(addr: &Address, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&addr.to_string())
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Address, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            match Address::from_str(&s) {
                Ok(addr) => Ok(addr.assume_checked()),
                Err(e) => Err(serde::de::Error::custom(e)),
            }
        }
    }

    pub mod wots_pubkeys {
        use super::*;
        use crate::types::WotsPublicKeys;
        use bitvm::chunk::api::{NUM_HASH, NUM_PUBS, NUM_U256};
        use bitvm::signatures::{Wots, Wots16, Wots32, signing_winternitz::WinternitzPublicKey};
        use goat::commitments::NUM_KICKOFF;
        use std::collections::HashMap;

        pub fn serialize<S>(pubkeys: &WotsPublicKeys, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut pubkeys_map: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
            let mut index = 0;
            // wots pk for groth16 proof
            for pk in pubkeys.1.0 {
                let v: Vec<Vec<u8>> = pk.iter().map(|x| x.to_vec()).collect();
                pubkeys_map.insert(index, v);
                index += 1;
            }
            for pk in pubkeys.1.1 {
                let v: Vec<Vec<u8>> = pk.iter().map(|x| x.to_vec()).collect();
                pubkeys_map.insert(index, v);
                index += 1;
            }
            for pk in pubkeys.1.2 {
                let v: Vec<Vec<u8>> = pk.iter().map(|x| x.to_vec()).collect();
                pubkeys_map.insert(index, v);
                index += 1;
            }

            // wots pk for kickoff bitcommitment
            let mut v_kickoff: Vec<Vec<u8>> = Vec::new();
            for pk in pubkeys.0.iter() {
                let pk_vec = bincode::serialize(pk).map_err(S::Error::custom)?;
                v_kickoff.push(pk_vec);
            }
            pubkeys_map.insert(index, v_kickoff);
            let map_vec = bincode::serialize(&pubkeys_map).map_err(S::Error::custom)?;
            serializer.serialize_bytes(&map_vec)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<WotsPublicKeys, D::Error>
        where
            D: Deserializer<'de>,
        {
            let map_vec = Vec::<u8>::deserialize(deserializer)?;
            let pubkeys_map: HashMap<u32, Vec<Vec<u8>>> =
                bincode::deserialize(&map_vec).map_err(serde::de::Error::custom)?;

            const W256_LEN: usize = Wots32::TOTAL_DIGIT_LEN as usize;
            const WHASH_LEN: usize = Wots16::TOTAL_DIGIT_LEN as usize;

            let mut pk0 = Vec::with_capacity(NUM_PUBS);
            let (min, max) = (0, NUM_PUBS);
            for i in min..max {
                let v = pubkeys_map.get(&(i as u32)).ok_or_else(|| {
                    serde::de::Error::custom(format!("Missing groth16pk.pub.[{i}]"))
                })?;

                if v.len() != W256_LEN {
                    return Err(serde::de::Error::custom("Invalid wots public-key length"));
                };

                let mut res = [[0u8; 20]; W256_LEN];
                for (j, bytes) in v.iter().enumerate() {
                    res[j] = bytes.as_slice().try_into().map_err(|_| {
                        serde::de::Error::custom("Invalid 20-byte chunk in wots256::PublicKey")
                    })?;
                }

                pk0.push(res);
            }
            let pk0: [<Wots32 as Wots>::PublicKey; NUM_PUBS] = pk0
                .try_into()
                .map_err(|_| serde::de::Error::custom("groth16pk.pub size mismatch"))?;

            let mut pk1 = Vec::with_capacity(NUM_U256);
            let (min, max) = (max, max + NUM_U256);
            for i in min..max {
                let v = pubkeys_map.get(&(i as u32)).ok_or_else(|| {
                    serde::de::Error::custom(format!("Missing groth16pk.wot256.[{i}]"))
                })?;

                if v.len() != W256_LEN {
                    return Err(serde::de::Error::custom("Invalid wots public-key length"));
                };

                let mut res = [[0u8; 20]; W256_LEN];
                for (j, bytes) in v.iter().enumerate() {
                    res[j] = bytes.as_slice().try_into().map_err(|_| {
                        serde::de::Error::custom("Invalid 20-byte chunk in wots256::PublicKey")
                    })?;
                }

                pk1.push(res);
            }
            let pk1: [<Wots32 as Wots>::PublicKey; NUM_U256] = pk1
                .try_into()
                .map_err(|_| serde::de::Error::custom("groth16pk.wots256 size mismatch"))?;

            let mut pk2 = Vec::with_capacity(NUM_HASH);
            let (min, max) = (max, max + NUM_HASH);
            for i in min..max {
                let v = pubkeys_map.get(&(i as u32)).ok_or_else(|| {
                    serde::de::Error::custom(format!("Missing groth16pk.wothash.[{i}]"))
                })?;

                if v.len() != WHASH_LEN {
                    return Err(serde::de::Error::custom("Invalid wots public-key length"));
                };

                let mut res = [[0u8; 20]; WHASH_LEN];
                for (j, bytes) in v.iter().enumerate() {
                    res[j] = bytes.as_slice().try_into().map_err(|_| {
                        serde::de::Error::custom("Invalid 20-byte chunk in wots_hash::PublicKey")
                    })?;
                }

                pk2.push(res);
            }
            let pk2: [<Wots16 as Wots>::PublicKey; NUM_HASH] = pk2
                .try_into()
                .map_err(|_| serde::de::Error::custom("groth16pk.wots_hash size mismatch"))?;

            let mut pk_kickoff: Vec<WinternitzPublicKey> = vec![];
            let (min, max) = (max, max + NUM_KICKOFF);
            for i in min..max {
                let v = pubkeys_map
                    .get(&(i as u32))
                    .ok_or_else(|| serde::de::Error::custom(format!("Missing kickoff_pk.[{i}]")))?;

                if v.len() != NUM_KICKOFF {
                    return Err(serde::de::Error::custom("Invalid kickoff wots public-key number"));
                }

                for (j, pk_bytes) in v.iter().enumerate() {
                    let pk = bincode::deserialize(pk_bytes).map_err(|e| {
                        serde::de::Error::custom(format!("Invalid kickoff_pk[{j}]: {e}"))
                    })?;
                    pk_kickoff.push(pk);
                }
            }
            let pk_kickoff: [WinternitzPublicKey; NUM_KICKOFF] = pk_kickoff
                .try_into()
                .unwrap_or_else(|_e| panic!("kickoff bitcom keys number not match"));

            Ok((Box::new(pk_kickoff), Box::new((pk0, pk1, pk2))))
        }
    }

    pub mod wots_seckeys {
        use serde::de::{SeqAccess, Visitor};
        use serde::ser::SerializeTuple;
        use serde::{Deserializer, Serializer, de::Error as DeError, ser::Error};
        use std::fmt;

        use crate::types::{
            Groth16WotsSecretKeys, KickoffWotsSecretKeys, NUM_KICKOFF, NUM_SIGS, WotsSecretKeys,
        };

        pub fn serialize<S>(keys: &WotsSecretKeys, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut tuple = serializer.serialize_tuple(2)?;

            // kickoff keys: serialize as Vec<Vec<u8>> via serde_json
            let kickoff_encoded: Vec<Vec<u8>> = keys
                .0
                .iter()
                .map(|k| serde_json::to_vec(k).map_err(S::Error::custom))
                .collect::<Result<_, _>>()?;
            tuple.serialize_element(&kickoff_encoded)?;

            // groth16 keys: just a Vec<String>
            let groth16_vec: Vec<String> = keys.1.to_vec();
            tuple.serialize_element(&groth16_vec)?;

            tuple.end()
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<WotsSecretKeys, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct WotsSecretKeysVisitor;

            impl<'de> Visitor<'de> for WotsSecretKeysVisitor {
                type Value = WotsSecretKeys;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "a tuple of (KickoffWotsSecretKeys, Groth16WotsSecretKeys)")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    // kickoff: Vec<Vec<u8>> -> KickoffWotsSecretKeys
                    let kickoff_encoded: Vec<Vec<u8>> = seq
                        .next_element()?
                        .ok_or_else(|| DeError::custom("Missing kickoff keys"))?;

                    if kickoff_encoded.len() != NUM_KICKOFF {
                        return Err(DeError::custom("kickoff keys length mismatch"));
                    }

                    let kickoff_keys: KickoffWotsSecretKeys = kickoff_encoded
                        .into_iter()
                        .map(|v| serde_json::from_slice(&v).map_err(DeError::custom))
                        .collect::<Result<Vec<_>, _>>()?
                        .try_into()
                        .map_err(|_| DeError::custom("failed to convert kickoff keys"))?;

                    // groth16: Vec<String> -> Groth16WotsSecretKeys
                    let groth16_vec: Vec<String> = seq
                        .next_element()?
                        .ok_or_else(|| DeError::custom("Missing groth16 keys"))?;

                    if groth16_vec.len() != NUM_SIGS {
                        return Err(DeError::custom("groth16 keys length mismatch"));
                    }

                    let groth16_keys: Groth16WotsSecretKeys = groth16_vec
                        .try_into()
                        .map_err(|_| DeError::custom("failed to convert groth16 keys"))?;

                    Ok((kickoff_keys, groth16_keys))
                }
            }

            deserializer.deserialize_tuple(2, WotsSecretKeysVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::operator::generate_wots_keys;
    use crate::types::{WotsPublicKeys, WotsSecretKeys, node_serializer};
    use bitcoin::Address;
    use serde::{Deserialize, Serialize};
    use std::fmt::Debug;
    use std::str::FromStr;

    fn mock_wots_secret_keys() -> WotsKeys {
        let (secs, pubs) = generate_wots_keys("seed");
        let address =
            Address::from_str("1CAGNhS5KPpeoZyL6DDNiKp85hCjZkvyYg").unwrap().assume_checked();
        WotsKeys { secs, pubs, address }
    }

    #[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct WotsKeys {
        #[serde(with = "node_serializer::wots_seckeys")]
        pub secs: WotsSecretKeys,
        #[serde(with = "node_serializer::wots_pubkeys")]
        pub pubs: WotsPublicKeys,
        #[serde(with = "node_serializer::address")]
        pub address: Address,
    }

    #[cfg(test)]
    impl Debug for WotsKeys {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "WotsKeys(..)")
        }
    }

    #[test]
    fn test_node_serializer() {
        let original = mock_wots_secret_keys();

        let json = serde_json::to_vec(&original).unwrap();
        let parsed: WotsKeys = serde_json::from_slice(&json).unwrap();
        assert_eq!(original, parsed);

        let encoded = bincode::serialize(&original).unwrap();
        let decoded: WotsKeys = bincode::deserialize(&encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
