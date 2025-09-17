use anyhow::{Result, bail};
use bitcoin::PrivateKey;
use bitcoin::{Address, Amount, Network, OutPoint, PublicKey, TxOut, XOnlyPublicKey, key::Keypair};
use bitvm::chunk::api::{
    NUM_HASH, NUM_PUBS, NUM_U256, PublicKeys as ProofWotsPubkeys,
    Signatures as Groth16ProofSignatures,
};
use bitvm::signatures::{WinternitzSecret, Wots, Wots32};
use goat::connectors::connector_0::Connector0;
use goat::connectors::connector_e::ConnectorE;
use goat::connectors::connector_z::ConnectorZ;
use goat::contexts::base::BaseContext;
use goat::contexts::operator::OperatorContext;
use goat::contexts::verifier::VerifierContext;
use goat::disprove_scripts::{
    GuestPubinSignatures, NUM_GUEST, NUM_GUEST_PUBS_ASSERT, NUM_GUEST_PUBS_EXTRA,
};
use goat::transactions::assert::{AssertCommitTimeoutTransaction, AssertInitTransaction};
use goat::transactions::base::Input;
use goat::transactions::challenge::ChallengeTransaction;
use goat::transactions::kickoff::KickoffTransaction;
use goat::transactions::pegin::{
    PegInConfirmTransaction, PegInDepositTransaction, PegInRefundTransaction,
};
use goat::transactions::prekickoff::{
    ChallengeIncompleteKickoffTransaction, ForceSkipKickoffTransaction, PrekickoffTransaction,
    QuickChallengeTransaction,
};
use goat::transactions::take1::Take1Transaction;
use goat::transactions::take2::Take2Transaction;
use goat::transactions::watchtower_challenge::{
    BlockhashCommitTimeoutTransaction, NackTransaction, WatchtowerChallengeInitTransaction,
    WatchtowerChallengeTimeoutTransaction,
};
use rand::{Rng, distributions::Alphanumeric};
use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type VerifyingKey = ark_groth16::VerifyingKey<ark_bn254::Bn254>;
pub type Groth16Proof = ark_groth16::Proof<ark_bn254::Bn254>;
pub type PublicInputs = Vec<ark_bn254::Fr>;

pub type OperatorWotsSignatures = (GuestPubinSignatures, Groth16ProofSignatures);

const NUM_SIGS: usize = NUM_GUEST + NUM_PUBS + NUM_HASH + NUM_U256;
pub type OperatorWotsSecretKeys = Box<[WinternitzSecret; NUM_SIGS]>;

pub type OperatorWotsPublicKeys = (
    [<Wots32 as Wots>::PublicKey; NUM_GUEST_PUBS_EXTRA],
    [<Wots32 as Wots>::PublicKey; NUM_GUEST_PUBS_ASSERT],
    Box<ProofWotsPubkeys>,
);

pub fn random_string(len: usize) -> String {
    rand::thread_rng().sample_iter(&Alphanumeric).take(len).map(char::from).collect()
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct UserInfo {
    pub depositor_evm_address: [u8; 20],
    pub txn_fees: [u64; 3], // [ peginDeposit , peginComfirm  peginReufnd ] fees in satoshi
    pub inputs: Vec<Input>,
    pub user_xonly_pubkey: XOnlyPublicKey,
    #[serde(with = "node_serializer::address")]
    pub user_change_address: Address,
    #[serde(with = "node_serializer::address")]
    pub user_refund_address: Address,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Bitvm2InstanceParameters {
    pub network: Network,
    pub instance_id: Uuid,
    pub user_info: UserInfo,
    pub pegin_amount: Amount,
    pub challenge_amount: Amount,
    pub committee_pubkeys: Vec<PublicKey>,
    pub committee_agg_pubkey: PublicKey,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct PrekickoffParameters {
    pub cur_prekickoff_txn: PrekickoffTransaction,
    pub replenish_fee_inputs: Vec<Input>,
    pub replenish_fee_prev_outs: Vec<TxOut>,
    pub fee_amount: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Bitvm2GraphParameters {
    pub instance_parameters: Bitvm2InstanceParameters,
    pub prekickoff_parameters: PrekickoffParameters,
    pub graph_id: Uuid,
    pub challenge_amount: Amount,
    pub operator_pubkey: PublicKey,
    #[serde(with = "node_serializer::wots_pubkeys")]
    pub operator_wots_pubkeys: OperatorWotsPublicKeys,
    #[serde(with = "node_serializer::address")]
    pub operator_receive_address: Address,
    pub watchtower_pubkeys: Vec<PublicKey>,
    pub hashlocks: Vec<[u8; 20]>, // one for each watchtower
}

impl Bitvm2InstanceParameters {
    pub fn check_parameters(&self) -> Result<bool> {
        // TODO
        bail!("Not implemented");
    }

    pub fn build_pegin_tx(
        &self,
    ) -> Result<(PegInDepositTransaction, PegInConfirmTransaction, PegInRefundTransaction)> {
        let network = self.network;
        let n_of_n_taproot_public_key = XOnlyPublicKey::from(self.committee_agg_pubkey);
        let user_taproot_public_key = self.user_info.user_xonly_pubkey;
        let connector_0 = Connector0::new(network, &n_of_n_taproot_public_key);
        let connector_z =
            ConnectorZ::new(network, &n_of_n_taproot_public_key, &user_taproot_public_key);
        let pegin_message = [
            get_magic_bytes(&network),
            self.instance_id.as_bytes().to_vec(),
            self.user_info.depositor_evm_address.to_vec(),
        ]
        .concat();

        let pegin_deposit = PegInDepositTransaction::new_unsigned(
            &connector_z,
            self.user_info.inputs.clone(),
            self.pegin_amount,
            Amount::from_sat(self.user_info.txn_fees[0]),
            self.user_info.user_change_address.clone(),
        )
        .map_err(|e| anyhow::anyhow!("fail to build pegin deposit txn: {e}"))?;
        let deposit_outpoint = Input {
            outpoint: OutPoint { txid: pegin_deposit.tx().compute_txid(), vout: 0 },
            amount: pegin_deposit.tx().output[0].value,
        };
        let pegin_confirm = PegInConfirmTransaction::new_for_validation(
            &connector_0,
            &connector_z,
            deposit_outpoint.clone(),
            Amount::from_sat(self.user_info.txn_fees[1]),
            pegin_message,
        )
        .map_err(|e| anyhow::anyhow!("fail to build pegin confirm txn: {e}"))?;
        let pegin_refund = PegInRefundTransaction::new_for_validation(
            &connector_z,
            deposit_outpoint,
            &self.user_info.user_refund_address,
            Amount::from_sat(self.user_info.txn_fees[2]),
        )
        .map_err(|e| anyhow::anyhow!("fail to build pegin refund txn: {e}"))?;

        Ok((pegin_deposit, pegin_confirm, pegin_refund))
    }

    pub fn get_verifier_context(
        &self,
        committee_member_keypair: Keypair,
    ) -> Result<VerifierContext> {
        let network = self.network;
        let committee_public_key = self.committee_agg_pubkey;
        let committee_taproot_public_key = XOnlyPublicKey::from(committee_public_key);
        let private_key = PrivateKey::new(committee_member_keypair.secret_key(), network);
        let committee_member_public_key = PublicKey::from_private_key(SECP256K1, &private_key);
        if !self.committee_pubkeys.contains(&committee_member_public_key) {
            bail!("The provided committee member keypair does not match any committee public key");
        }
        Ok(VerifierContext {
            network,
            verifier_keypair: committee_member_keypair,
            verifier_public_key: committee_member_public_key,
            n_of_n_public_keys: self.committee_pubkeys.clone(),
            n_of_n_public_key: committee_public_key,
            n_of_n_taproot_public_key: committee_taproot_public_key,
        })
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

impl Bitvm2GraphParameters {
    pub fn get_operator_context(&self, operator_keypair: Keypair) -> Result<OperatorContext> {
        let network = self.instance_parameters.network;
        let operator_public_key = self.operator_pubkey;
        let operator_taproot_public_key = XOnlyPublicKey::from(operator_public_key);
        let committee_public_key = self.instance_parameters.committee_agg_pubkey;
        let committee_taproot_public_key = XOnlyPublicKey::from(committee_public_key);
        if operator_public_key
            != PublicKey::from_private_key(
                SECP256K1,
                &PrivateKey::new(operator_keypair.secret_key(), network),
            )
        {
            bail!("The provided operator keypair does not match the operator public key");
        }
        Ok(OperatorContext {
            network,
            operator_keypair,
            operator_public_key,
            operator_taproot_public_key,

            n_of_n_public_keys: self.instance_parameters.committee_pubkeys.clone(),
            n_of_n_public_key: committee_public_key,
            n_of_n_taproot_public_key: committee_taproot_public_key,
        })
    }

    pub fn get_base_context(&self) -> BaseBitvmContext {
        self.instance_parameters.get_base_context()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Bitvm2Graph {
    pub(crate) operator_pre_signed: bool,
    pub(crate) committee_pre_signed: bool,
    pub parameters: Bitvm2GraphParameters,

    pub cur_prekickoff: PrekickoffTransaction,
    pub next_prekickoff: PrekickoffTransaction,
    pub force_skip_kickoff: ForceSkipKickoffTransaction,
    pub quick_challenge: QuickChallengeTransaction,
    pub challenge_incomplete_kickoff: ChallengeIncompleteKickoffTransaction,

    pub pegin: PegInConfirmTransaction,
    pub kickoff: KickoffTransaction,
    pub take1: Take1Transaction,
    pub challenge: ChallengeTransaction,
    pub take2: Take2Transaction,

    pub watchtower_challenge_init: WatchtowerChallengeInitTransaction,
    pub watchtower_challenge_timeout_txns: Vec<WatchtowerChallengeTimeoutTransaction>,
    pub nack_txns: Vec<NackTransaction>,
    pub blockhash_commit_timeout: BlockhashCommitTimeoutTransaction,

    pub assert_init: AssertInitTransaction,
    pub assert_commit_timeout_txns: Vec<AssertCommitTimeoutTransaction>,

    pub connector_e: ConnectorE,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SimplifiedBitvm2Graph {
    // TODO
}

impl Bitvm2Graph {
    pub fn operator_pre_signed(&self) -> bool {
        self.operator_pre_signed
    }
    pub fn committee_pre_signed(&self) -> bool {
        self.committee_pre_signed
    }
    // TODO: from_simplified & to_simplified
}

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
        use crate::types::OperatorWotsPublicKeys;
        use bitvm::chunk::api::{NUM_HASH, NUM_PUBS, NUM_U256};
        use bitvm::signatures::{Wots, Wots16, Wots32};
        use goat::disprove_scripts::{NUM_GUEST_PUBS_ASSERT, NUM_GUEST_PUBS_EXTRA};
        use std::collections::HashMap;

        pub fn serialize<S>(
            pubkeys: &OperatorWotsPublicKeys,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut pubkeys_map: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
            let mut index = 0;

            // wots pk for guest pubin
            for pk in pubkeys.0 {
                let v: Vec<Vec<u8>> = pk.iter().map(|x| x.to_vec()).collect();
                pubkeys_map.insert(index, v);
                index += 1;
            }
            for pk in pubkeys.1 {
                let v: Vec<Vec<u8>> = pk.iter().map(|x| x.to_vec()).collect();
                pubkeys_map.insert(index, v);
                index += 1;
            }
            // wots pk for groth16 proof
            for pk in pubkeys.2.0 {
                let v: Vec<Vec<u8>> = pk.iter().map(|x| x.to_vec()).collect();
                pubkeys_map.insert(index, v);
                index += 1;
            }
            for pk in pubkeys.2.1 {
                let v: Vec<Vec<u8>> = pk.iter().map(|x| x.to_vec()).collect();
                pubkeys_map.insert(index, v);
                index += 1;
            }
            for pk in pubkeys.2.2 {
                let v: Vec<Vec<u8>> = pk.iter().map(|x| x.to_vec()).collect();
                pubkeys_map.insert(index, v);
                index += 1;
            }
            let map_vec = bincode::serialize(&pubkeys_map).map_err(S::Error::custom)?;
            serializer.serialize_bytes(&map_vec)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<OperatorWotsPublicKeys, D::Error>
        where
            D: Deserializer<'de>,
        {
            let map_vec = Vec::<u8>::deserialize(deserializer)?;
            let pubkeys_map: HashMap<u32, Vec<Vec<u8>>> =
                bincode::deserialize(&map_vec).map_err(serde::de::Error::custom)?;

            fn extract_wots_pubkeys<W, const N: usize, E>(
                pubkeys_map: &HashMap<u32, Vec<Vec<u8>>>,
                range: std::ops::Range<u32>,
                label: &str,
            ) -> Result<[<W as Wots>::PublicKey; N], E>
            where
                W: Wots,
                E: serde::de::Error,
            {
                let digit_len = W::TOTAL_DIGIT_LEN as usize;
                let mut out = Vec::with_capacity(N);

                for i in range {
                    let v = pubkeys_map
                        .get(&i)
                        .ok_or_else(|| E::custom(format!("Missing {label}[{i}]")))?;

                    if v.len() != digit_len {
                        return Err(E::custom(format!(
                            "Invalid {label}[{i}] length (expected {digit_len})"
                        )));
                    }

                    let mut res: Vec<[u8; 20]> = Vec::with_capacity(digit_len);
                    for (j, bytes) in v.iter().enumerate() {
                        res.push(bytes.as_slice().try_into().map_err(|_| {
                            E::custom(format!("Invalid 20-byte chunk in {label}[{i}][{j}]"))
                        })?);
                    }

                    let res: <W as Wots>::PublicKey = res.try_into().map_err(|_| {
                        E::custom(format!("{label}[{i}] size mismatch (expected {digit_len})"))
                    })?;
                    out.push(res);
                }

                out.try_into()
                    .map_err(|_| E::custom(format!("{label} size mismatch (expected {N})")))
            }

            let mut idx = 0u32;

            let pk0 = extract_wots_pubkeys::<Wots32, NUM_GUEST_PUBS_EXTRA, D::Error>(
                &pubkeys_map,
                idx..idx + NUM_GUEST_PUBS_EXTRA as u32,
                "guestpk.extra",
            )?;
            idx += NUM_GUEST_PUBS_EXTRA as u32;

            let pk1 = extract_wots_pubkeys::<Wots32, NUM_GUEST_PUBS_ASSERT, D::Error>(
                &pubkeys_map,
                idx..idx + NUM_GUEST_PUBS_ASSERT as u32,
                "guestpk.assert",
            )?;
            idx += NUM_GUEST_PUBS_ASSERT as u32;

            let pk20 = extract_wots_pubkeys::<Wots32, NUM_PUBS, D::Error>(
                &pubkeys_map,
                idx..idx + NUM_PUBS as u32,
                "groth16pk.pub",
            )?;
            idx += NUM_PUBS as u32;

            let pk21 = extract_wots_pubkeys::<Wots32, NUM_U256, D::Error>(
                &pubkeys_map,
                idx..idx + NUM_U256 as u32,
                "groth16pk.wots256",
            )?;
            idx += NUM_U256 as u32;

            let pk22 = extract_wots_pubkeys::<Wots16, NUM_HASH, D::Error>(
                &pubkeys_map,
                idx..idx + NUM_HASH as u32,
                "groth16pk.wots_hash",
            )?;

            Ok((pk0, pk1, Box::new((pk20, pk21, pk22))))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::operator::generate_wots_keys;
    use crate::types::{OperatorWotsPublicKeys, node_serializer};
    use bitcoin::Address;
    use serde::{Deserialize, Serialize};
    use std::fmt::Debug;
    use std::str::FromStr;

    fn mock_wots_secret_keys() -> WotsKeys {
        let (_, pubs) = generate_wots_keys("seed");
        let address =
            Address::from_str("1CAGNhS5KPpeoZyL6DDNiKp85hCjZkvyYg").unwrap().assume_checked();
        WotsKeys { pubs, address }
    }

    #[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct WotsKeys {
        #[serde(with = "node_serializer::wots_pubkeys")]
        pub pubs: OperatorWotsPublicKeys,
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
