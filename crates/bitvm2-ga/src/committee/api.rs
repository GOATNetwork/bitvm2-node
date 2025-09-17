use crate::types::Bitvm2Graph;
use anyhow::{Result, bail};
use bitcoin::{PublicKey, Transaction, XOnlyPublicKey};
use bitcoin::{key::Keypair, taproot::Signature as TaprootSignature};
use goat::connectors::assert_connectors::generate_chunked_assert_commit_connectors;
use goat::connectors::connector_0::Connector0;
use goat::connectors::connector_a::ConnectorA;
use goat::connectors::connector_d::ConnectorD;
use goat::connectors::connector_f::ConnectorF;
use goat::connectors::connector_g::ConnectorG;
use goat::connectors::connector_z::ConnectorZ;
use goat::connectors::watchtower_connectors::{
    AckConnector, WatchctowerConnectors, WatchtowerChallengeConnector,
};
use goat::contexts::base::generate_n_of_n_public_key;
use goat::transactions::pre_signed_musig2::{get_nonce_message, verify_public_nonce};
use goat::transactions::{base::BaseTransaction, signing_musig2::generate_aggregated_nonce};
use hex::FromHex;
use musig2::{AggNonce, PartialSignature, PubNonce, SecNonce};
use secp256k1::schnorr::Signature as SchnorrSignature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub fn key_aggregation(pubkeys: &[PublicKey]) -> PublicKey {
    generate_n_of_n_public_key(pubkeys).0
}

pub fn take1_pre_sign_num() -> usize {
    1
}
pub fn take2_pre_sign_num() -> usize {
    1
}
pub fn challenge_pre_sign_num() -> usize {
    1
}
pub fn watchtower_challenge_timeout_pre_sign_num(watchtower_num: usize) -> usize {
    watchtower_num
}
pub fn nack_pre_sign_num(watchtower_num: usize) -> usize {
    2 * watchtower_num
}
pub fn blockhash_commit_timeout_pre_sign_num() -> usize {
    2
}
pub fn assert_commit_timeout_pre_sign_num(assert_commit_num: usize) -> usize {
    2 * assert_commit_num
}

pub fn sign_pegin_confirm(
    graph: &Bitvm2Graph,
    committee_member_keypair: Keypair,
    committee_member_sec_nonce: SecNonce,
    committee_agg_nonce: AggNonce,
) -> Result<PartialSignature> {
    let mut pegin_confirm = graph.parameters.instance_parameters.build_pegin_tx()?.1;
    let verifier_context =
        graph.parameters.instance_parameters.get_verifier_context(committee_member_keypair)?;
    pegin_confirm
        .sign_input_0_musig2(&verifier_context, &committee_member_sec_nonce, &committee_agg_nonce)
        .map_err(|e| anyhow::anyhow!("fail to sign pegin confirm {}: {e}", pegin_confirm.name()))
}

pub fn agg_and_push_pegin_confirm_sigs(
    graph: &Bitvm2Graph,
    partial_sigs: Vec<PartialSignature>,
    agg_nonce: &AggNonce,
) -> Result<Transaction> {
    let mut pegin_confirm = graph.parameters.instance_parameters.build_pegin_tx()?.1;
    let context = graph.parameters.instance_parameters.get_base_context();
    let agg_sig = pegin_confirm
        .aggregate_input_0_musig2_signatures(&context, partial_sigs, agg_nonce)
        .map_err(|e| {
            anyhow::anyhow!("fail to aggregate pegin confirm {}: {e}", pegin_confirm.name())
        })?;
    let connector_z = ConnectorZ::new(
        graph.parameters.instance_parameters.network,
        &XOnlyPublicKey::from(graph.parameters.instance_parameters.committee_agg_pubkey),
        &graph.parameters.instance_parameters.user_info.user_xonly_pubkey,
    );
    pegin_confirm.push_input_0_signature(&connector_z, agg_sig);
    Ok(pegin_confirm.finalize())
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct CommitteeMusig2Data<T> {
    pub take1: Vec<T>,
    pub take2: Vec<T>,
    pub challenge: Vec<T>,
    pub watchtower_challenge_timeout: Vec<T>,
    pub nack: Vec<T>,
    pub blockhash_commit_timeout: Vec<T>,
    pub assert_commit_timeout: Vec<T>,
}

pub type CommitteeSecNonces = CommitteeMusig2Data<SecNonce>;
pub type CommitteePubNonces = CommitteeMusig2Data<PubNonce>;
pub type CommitteeNonceSignatures = CommitteeMusig2Data<SchnorrSignature>;
pub type CommitteeAggNonces = CommitteeMusig2Data<AggNonce>;
pub type CommitteePartialSignatures = CommitteeMusig2Data<PartialSignature>;
pub type CommitteeSignatures = CommitteeMusig2Data<TaprootSignature>;

impl<T> CommitteeMusig2Data<T> {
    pub fn validate_length(&self, watchtower_num: usize, assert_commit_num: usize) -> Result<()> {
        if self.take1.len() != take1_pre_sign_num() {
            bail!("invalid number of take1");
        }
        if self.take2.len() != take2_pre_sign_num() {
            bail!("invalid number of take2");
        }
        if self.challenge.len() != challenge_pre_sign_num() {
            bail!("invalid number of challenge");
        }
        if self.blockhash_commit_timeout.len() != blockhash_commit_timeout_pre_sign_num() {
            bail!("invalid number of blockhash_commit_timeout");
        }
        if self.watchtower_challenge_timeout.len()
            != watchtower_challenge_timeout_pre_sign_num(watchtower_num)
        {
            bail!("invalid number of watchtower_challenge_timeout");
        }
        if self.nack.len() != nack_pre_sign_num(watchtower_num) {
            bail!("invalid number of nack");
        }
        if self.assert_commit_timeout.len() != assert_commit_timeout_pre_sign_num(assert_commit_num)
        {
            bail!("invalid number of assert_commit_timeout");
        }
        Ok(())
    }

    pub fn new_empty() -> Self {
        CommitteeMusig2Data {
            take1: vec![],
            take2: vec![],
            challenge: vec![],
            watchtower_challenge_timeout: vec![],
            nack: vec![],
            blockhash_commit_timeout: vec![],
            assert_commit_timeout: vec![],
        }
    }
}

pub fn committee_pre_sign(
    committee_member_keypair: Keypair,
    committee_member_sec_nonce: CommitteeSecNonces,
    committee_agg_nonce: CommitteeAggNonces,
    graph: &mut Bitvm2Graph,
) -> Result<CommitteePartialSignatures> {
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    let assert_commit_num = graph.assert_commit_timeout_txns.len();
    committee_member_sec_nonce.validate_length(watchtower_num, assert_commit_num)?;
    committee_agg_nonce.validate_length(watchtower_num, assert_commit_num)?;

    let verifier_context =
        graph.parameters.instance_parameters.get_verifier_context(committee_member_keypair)?;
    let mut res = CommitteePartialSignatures::new_empty();

    {
        // take-1
        let sec_nonces = committee_member_sec_nonce.take1.try_into().unwrap();
        let agg_nonces = committee_agg_nonce.take1.try_into().unwrap();
        match graph.take1.pre_sign(&verifier_context, &sec_nonces, &agg_nonces) {
            Ok(v) => res.take1 = v.to_vec(),
            Err(e) => bail!("fail to pre-sign {}: {e}", graph.take1.name()),
        };
    }

    {
        // take-2
        let sec_nonces = committee_member_sec_nonce.take2.try_into().unwrap();
        let agg_nonces = committee_agg_nonce.take2.try_into().unwrap();
        match graph.take2.pre_sign(&verifier_context, &sec_nonces, &agg_nonces) {
            Ok(v) => res.take2 = v.to_vec(),
            Err(e) => bail!("fail to pre-sign {}: {e}", graph.take2.name()),
        };
    }

    {
        // challenge
        let sec_nonces = committee_member_sec_nonce.challenge.try_into().unwrap();
        let agg_nonces = committee_agg_nonce.challenge.try_into().unwrap();
        match graph.challenge.pre_sign(&verifier_context, &sec_nonces, &agg_nonces) {
            Ok(v) => res.challenge = v.to_vec(),
            Err(e) => bail!("fail to pre-sign {}: {e}", graph.challenge.name()),
        };
    }

    {
        // watchtower_challenge_timeout
        let mut watchtower_challenge_timeout_sigs = vec![];
        for (i, watchtower_challenge_timeout_tx) in
            graph.watchtower_challenge_timeout_txns.iter_mut().enumerate()
        {
            let sec_nonces = [committee_member_sec_nonce.watchtower_challenge_timeout[i].clone()];
            let agg_nonces = [committee_agg_nonce.watchtower_challenge_timeout[i].clone()];
            let sigs = watchtower_challenge_timeout_tx
                .pre_sign(&verifier_context, &sec_nonces, &agg_nonces)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "fail to pre-sign {}: {e}",
                        watchtower_challenge_timeout_tx.name()
                    )
                })?;
            watchtower_challenge_timeout_sigs.extend(sigs);
        }
        res.watchtower_challenge_timeout = watchtower_challenge_timeout_sigs;
    }

    {
        // nack
        let mut nack_sigs = vec![];
        for (i, nack_tx) in graph.nack_txns.iter_mut().enumerate() {
            let sec_nonces = [
                committee_member_sec_nonce.nack[i * 2].clone(),
                committee_member_sec_nonce.nack[i * 2 + 1].clone(),
            ];
            let agg_nonces = [
                committee_agg_nonce.nack[i * 2].clone(),
                committee_agg_nonce.nack[i * 2 + 1].clone(),
            ];
            let sigs = nack_tx
                .pre_sign(&verifier_context, &sec_nonces, &agg_nonces)
                .map_err(|e| anyhow::anyhow!("fail to pre-sign {}: {e}", nack_tx.name()))?;
            nack_sigs.extend(sigs);
        }
        res.nack = nack_sigs;
    }

    {
        // blockhash-commit-timeout
        let sec_nonces = committee_member_sec_nonce.blockhash_commit_timeout.try_into().unwrap();
        let agg_nonces = committee_agg_nonce.blockhash_commit_timeout.try_into().unwrap();
        match graph.blockhash_commit_timeout.pre_sign(&verifier_context, &sec_nonces, &agg_nonces) {
            Ok(v) => res.blockhash_commit_timeout = v.to_vec(),
            Err(e) => bail!("fail to pre-sign {}: {e}", graph.blockhash_commit_timeout.name()),
        }
    }

    {
        // assert-commit-timeout
        let mut assert_commit_timeout_sigs = vec![];
        for (i, assert_commit_timeout_tx) in graph.assert_commit_timeout_txns.iter_mut().enumerate()
        {
            let sec_nonces = [
                committee_member_sec_nonce.assert_commit_timeout[i * 2].clone(),
                committee_member_sec_nonce.assert_commit_timeout[i * 2 + 1].clone(),
            ];
            let agg_nonces = [
                committee_agg_nonce.assert_commit_timeout[i * 2].clone(),
                committee_agg_nonce.assert_commit_timeout[i * 2 + 1].clone(),
            ];
            let sigs = assert_commit_timeout_tx
                .pre_sign(&verifier_context, &sec_nonces, &agg_nonces)
                .map_err(|e| {
                    anyhow::anyhow!("fail to pre-sign {}: {e}", assert_commit_timeout_tx.name())
                })?;
            assert_commit_timeout_sigs.extend(sigs);
        }
        res.assert_commit_timeout = assert_commit_timeout_sigs;
    }

    Ok(res)
}

pub fn nonce_aggregation(pub_nonces: &Vec<PubNonce>) -> AggNonce {
    generate_aggregated_nonce(pub_nonces)
}

pub fn nonces_aggregation(pub_nonces_vec: &Vec<CommitteePubNonces>) -> CommitteeAggNonces {
    fn aggregate_field<F>(rows: &Vec<CommitteePubNonces>, get: F) -> Vec<AggNonce>
    where
        F: Fn(&CommitteePubNonces) -> &Vec<PubNonce>,
    {
        if rows.is_empty() {
            return Vec::new();
        }

        let expected = get(&rows[0]).len();

        for (idx, r) in rows.iter().enumerate() {
            assert!(
                get(r).len() == expected,
                "length mismatch on row {}: expected {}, got {}",
                idx,
                expected,
                get(r).len()
            );
        }

        (0..expected)
            .map(|i| {
                let column: Vec<PubNonce> = rows.iter().map(|r| get(r)[i].clone()).collect();
                nonce_aggregation(&column)
            })
            .collect()
    }

    CommitteeAggNonces {
        take1: aggregate_field(&pub_nonces_vec, |c| &c.take1),
        take2: aggregate_field(&pub_nonces_vec, |c| &c.take2),
        challenge: aggregate_field(&pub_nonces_vec, |c| &c.challenge),
        watchtower_challenge_timeout: aggregate_field(&pub_nonces_vec, |c| {
            &c.watchtower_challenge_timeout
        }),
        nack: aggregate_field(&pub_nonces_vec, |c| &c.nack),
        blockhash_commit_timeout: aggregate_field(&pub_nonces_vec, |c| &c.blockhash_commit_timeout),
        assert_commit_timeout: aggregate_field(&pub_nonces_vec, |c| &c.assert_commit_timeout),
    }
}

pub fn signature_aggregation(
    partial_sigs: &Vec<CommitteePartialSignatures>,
    agg_nonces: &CommitteeAggNonces,
    graph: &Bitvm2Graph,
) -> Result<CommitteeSignatures> {
    let context = graph.parameters.get_base_context();
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    let assert_commit_num = graph.assert_commit_timeout_txns.len();
    agg_nonces.validate_length(watchtower_num, assert_commit_num)?;
    for r in partial_sigs {
        r.validate_length(watchtower_num, assert_commit_num)?;
    }

    let mut res: CommitteeSignatures = CommitteeSignatures::new_empty();

    // take1
    let take1_agg_nonces = agg_nonces.take1.clone().try_into().unwrap();
    let take1_partial_sigs = [partial_sigs.iter().map(|r| r.take1[0].clone()).collect()];
    match graph.take1.aggregate_pre_sigs(&context, &take1_partial_sigs, &take1_agg_nonces) {
        Ok(v) => res.take1 = v.to_vec(),
        Err(e) => bail!("fail to aggregate pre-sigs {}: {e}", graph.take1.name()),
    };

    // take2
    let take2_agg_nonces = agg_nonces.take2.clone().try_into().unwrap();
    let take2_partial_sigs = [partial_sigs.iter().map(|r| r.take2[0].clone()).collect()];
    match graph.take2.aggregate_pre_sigs(&context, &take2_partial_sigs, &take2_agg_nonces) {
        Ok(v) => res.take2 = v.to_vec(),
        Err(e) => bail!("fail to aggregate pre-sigs {}: {e}", graph.take2.name()),
    };

    // challenge
    let challenge_agg_nonces = agg_nonces.challenge.clone().try_into().unwrap();
    let challenge_partial_sigs = [partial_sigs.iter().map(|r| r.challenge[0].clone()).collect()];
    match graph.challenge.aggregate_pre_sigs(
        &context,
        &challenge_partial_sigs,
        &challenge_agg_nonces,
    ) {
        Ok(v) => res.challenge = v.to_vec(),
        Err(e) => bail!("fail to aggregate pre-sigs {}: {e}", graph.challenge.name()),
    };

    // blockhash-commit-timeout
    let blockhash_commit_timeout_agg_nonces =
        agg_nonces.blockhash_commit_timeout.clone().try_into().unwrap();
    let mut blockhash_commit_timeout_partial_sigs = [vec![], vec![]];
    partial_sigs.iter().for_each(|r| {
        blockhash_commit_timeout_partial_sigs[0].push(r.blockhash_commit_timeout[0].clone());
        blockhash_commit_timeout_partial_sigs[1].push(r.blockhash_commit_timeout[1].clone());
    });
    match graph.blockhash_commit_timeout.aggregate_pre_sigs(
        &context,
        &blockhash_commit_timeout_partial_sigs,
        &blockhash_commit_timeout_agg_nonces,
    ) {
        Ok(v) => res.blockhash_commit_timeout = v.to_vec(),
        Err(e) => {
            bail!("fail to aggregate pre-sigs {}: {e}", graph.blockhash_commit_timeout.name())
        }
    };

    // watchtower_challenge_timeout
    let mut watchtower_challenge_timeout_sigs = vec![];
    for (i, watchtower_challenge_timeout_tx) in
        graph.watchtower_challenge_timeout_txns.iter().enumerate()
    {
        let _agg_nonces = [agg_nonces.watchtower_challenge_timeout[i].clone()];
        let mut _partial_sigs = [vec![]];
        partial_sigs.iter().for_each(|r| {
            _partial_sigs[0].push(r.watchtower_challenge_timeout[i].clone());
        });
        let sigs = watchtower_challenge_timeout_tx
            .aggregate_pre_sigs(&context, &_partial_sigs, &_agg_nonces)
            .map_err(|e| {
                anyhow::anyhow!(
                    "fail to aggregate pre-sigs {}: {e}",
                    watchtower_challenge_timeout_tx.name()
                )
            })?;
        watchtower_challenge_timeout_sigs.extend(sigs);
    }
    res.watchtower_challenge_timeout = watchtower_challenge_timeout_sigs;

    // nack
    let mut nack_sigs = vec![];
    for (i, nack_tx) in graph.nack_txns.iter().enumerate() {
        let _agg_nonces = [agg_nonces.nack[i * 2].clone(), agg_nonces.nack[i * 2 + 1].clone()];
        let mut _partial_sigs = [vec![], vec![]];
        partial_sigs.iter().for_each(|r| {
            _partial_sigs[0].push(r.nack[i * 2].clone());
            _partial_sigs[1].push(r.nack[i * 2 + 1].clone());
        });
        let sigs = nack_tx
            .aggregate_pre_sigs(&context, &_partial_sigs, &_agg_nonces)
            .map_err(|e| anyhow::anyhow!("fail to aggregate pre-sigs {}: {e}", nack_tx.name()))?;
        nack_sigs.extend(sigs);
    }
    res.nack = nack_sigs;

    // assert-commit-timeout
    let mut assert_commit_timeout_sigs = vec![];
    for (i, assert_commit_timeout_tx) in graph.assert_commit_timeout_txns.iter().enumerate() {
        let _agg_nonces = [
            agg_nonces.assert_commit_timeout[i * 2].clone(),
            agg_nonces.assert_commit_timeout[i * 2 + 1].clone(),
        ];
        let mut _partial_sigs = [vec![], vec![]];
        partial_sigs.iter().for_each(|r| {
            _partial_sigs[0].push(r.assert_commit_timeout[i * 2].clone());
            _partial_sigs[1].push(r.assert_commit_timeout[i * 2 + 1].clone());
        });
        let sigs = assert_commit_timeout_tx
            .aggregate_pre_sigs(&context, &_partial_sigs, &_agg_nonces)
            .map_err(|e| {
                anyhow::anyhow!(
                    "fail to aggregate pre-sigs {}: {e}",
                    assert_commit_timeout_tx.name()
                )
            })?;
        assert_commit_timeout_sigs.extend(sigs);
    }
    res.assert_commit_timeout = assert_commit_timeout_sigs;

    Ok(res)
}

pub fn push_committee_pre_signatures(
    graph: &mut Bitvm2Graph,
    sigs: &CommitteeSignatures,
) -> Result<()> {
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    let assert_commit_num = graph.assert_commit_timeout_txns.len();
    if graph.committee_pre_signed {
        bail!("already pre-signed by committee".to_string())
    };
    sigs.validate_length(watchtower_num, assert_commit_num)?;

    let network = graph.parameters.instance_parameters.network;
    let n_of_n_taproot_public_key =
        XOnlyPublicKey::from(graph.parameters.instance_parameters.committee_agg_pubkey);
    let operator_taproot_public_key = XOnlyPublicKey::from(graph.parameters.operator_pubkey);
    let connector_0 = Connector0::new(network, &n_of_n_taproot_public_key);
    let connector_a =
        ConnectorA::new(network, &operator_taproot_public_key, &n_of_n_taproot_public_key);
    let connector_d =
        ConnectorD::new(network, &operator_taproot_public_key, &n_of_n_taproot_public_key);
    let blockhash_wots_pubkey = &graph.parameters.operator_wots_pubkeys.0[0];
    let connector_f =
        ConnectorF::new(network, &operator_taproot_public_key, &n_of_n_taproot_public_key);
    let connector_g = ConnectorG::new(
        network,
        &n_of_n_taproot_public_key,
        &operator_taproot_public_key,
        blockhash_wots_pubkey,
    );
    let watchtower_connectors_array = (0..watchtower_num)
        .map(|i| {
            (
                WatchtowerChallengeConnector::new(
                    network,
                    &operator_taproot_public_key,
                    &XOnlyPublicKey::from(graph.parameters.watchtower_pubkeys[i]),
                ),
                AckConnector::new(
                    network,
                    &n_of_n_taproot_public_key,
                    &graph.parameters.hashlocks[i],
                ),
            )
        })
        .collect::<Vec<WatchctowerConnectors>>();
    let assert_wots_pubkeys = (
        graph.parameters.operator_wots_pubkeys.1.clone(),
        *graph.parameters.operator_wots_pubkeys.2,
    );
    let assert_commit_connectors = generate_chunked_assert_commit_connectors(
        network,
        &n_of_n_taproot_public_key,
        assert_wots_pubkeys,
    );

    // take1
    graph.take1.push_pre_sigs(&connector_0, sigs.take1.clone().try_into().unwrap());

    // take2
    graph.take2.push_pre_sigs(&connector_0, sigs.take2.clone().try_into().unwrap());

    // challenge
    graph.challenge.push_pre_sigs(&connector_a, sigs.challenge.clone().try_into().unwrap());

    // blockhash-commit-timeout
    graph.blockhash_commit_timeout.push_pre_sigs(
        &connector_g,
        &connector_f,
        sigs.blockhash_commit_timeout.clone().try_into().unwrap(),
    );

    // watchtower_challenge_timeout
    for (i, watchtower_challenge_timeout_tx) in
        graph.watchtower_challenge_timeout_txns.iter_mut().enumerate()
    {
        watchtower_challenge_timeout_tx.push_pre_sigs(
            &watchtower_connectors_array[i],
            sigs.watchtower_challenge_timeout[i..(i + 1)].try_into().unwrap(),
        );
    }

    // nack
    for (i, nack_tx) in graph.nack_txns.iter_mut().enumerate() {
        nack_tx.push_pre_sigs(
            &watchtower_connectors_array[i],
            &connector_f,
            sigs.nack[i * 2..(i * 2 + 2)].try_into().unwrap(),
        );
    }

    // assert-commit-timeout
    for (i, assert_commit_timeout_tx) in graph.assert_commit_timeout_txns.iter_mut().enumerate() {
        assert_commit_timeout_tx.push_pre_sigs(
            &assert_commit_connectors[i],
            &connector_d,
            sigs.assert_commit_timeout[i * 2..(i * 2 + 2)].try_into().unwrap(),
        );
    }

    graph.committee_pre_signed = true;
    Ok(())
}

pub fn generate_keypair_from_seed(seed: String) -> Keypair {
    let keypair_secret = sha256(&format!("{seed}/master"));
    Keypair::from_seckey_str_global(&keypair_secret).unwrap()
}

pub fn generate_nonce_from_seed(
    seed: String,
    graph_index: usize,
    signer_keypair: Keypair,
    watchtower_num: usize,
    assert_commit_num: usize,
) -> (CommitteePubNonces, CommitteeSecNonces, CommitteeNonceSignatures) {
    let graph_seed = sha256_with_id(&seed, graph_index);
    let mut pub_nonces = CommitteePubNonces::new_empty();
    let mut sec_nonces = CommitteeSecNonces::new_empty();
    let mut nonce_sigs = CommitteeNonceSignatures::new_empty();
    let mut index = 0;
    {
        // take1
        for _ in 0..take1_pre_sign_num() {
            let (sec_nonce, pub_nonce, nonce_sig) =
                generate_nonce(signer_keypair, &graph_seed, index);
            pub_nonces.take1.push(pub_nonce);
            sec_nonces.take1.push(sec_nonce);
            nonce_sigs.take1.push(nonce_sig);
            index += 1;
        }
    }
    {
        // take2
        for _ in 0..take2_pre_sign_num() {
            let (sec_nonce, pub_nonce, nonce_sig) =
                generate_nonce(signer_keypair, &graph_seed, index);
            pub_nonces.take2.push(pub_nonce);
            sec_nonces.take2.push(sec_nonce);
            nonce_sigs.take2.push(nonce_sig);
            index += 1;
        }
    }
    {
        // challenge
        for _ in 0..challenge_pre_sign_num() {
            let (sec_nonce, pub_nonce, nonce_sig) =
                generate_nonce(signer_keypair, &graph_seed, index);
            pub_nonces.challenge.push(pub_nonce);
            sec_nonces.challenge.push(sec_nonce);
            nonce_sigs.challenge.push(nonce_sig);
            index += 1;
        }
    }
    {
        // watchtower_challenge_timeout
        for _ in 0..watchtower_challenge_timeout_pre_sign_num(watchtower_num) {
            let (sec_nonce, pub_nonce, nonce_sig) =
                generate_nonce(signer_keypair, &graph_seed, index);
            pub_nonces.watchtower_challenge_timeout.push(pub_nonce);
            sec_nonces.watchtower_challenge_timeout.push(sec_nonce);
            nonce_sigs.watchtower_challenge_timeout.push(nonce_sig);
            index += 1;
        }
    }
    {
        // nack
        for _ in 0..nack_pre_sign_num(watchtower_num) {
            let (sec_nonce, pub_nonce, nonce_sig) =
                generate_nonce(signer_keypair, &graph_seed, index);
            pub_nonces.nack.push(pub_nonce);
            sec_nonces.nack.push(sec_nonce);
            nonce_sigs.nack.push(nonce_sig);
            index += 1;
        }
    }
    {
        // blockhash-commit-timeout
        for _ in 0..blockhash_commit_timeout_pre_sign_num() {
            let (sec_nonce, pub_nonce, nonce_sig) =
                generate_nonce(signer_keypair, &graph_seed, index);
            pub_nonces.blockhash_commit_timeout.push(pub_nonce);
            sec_nonces.blockhash_commit_timeout.push(sec_nonce);
            nonce_sigs.blockhash_commit_timeout.push(nonce_sig);
            index += 1;
        }
    }
    {
        // assert-commit-timeout
        for _ in 0..assert_commit_timeout_pre_sign_num(assert_commit_num) {
            let (sec_nonce, pub_nonce, nonce_sig) =
                generate_nonce(signer_keypair, &graph_seed, index);
            pub_nonces.assert_commit_timeout.push(pub_nonce);
            sec_nonces.assert_commit_timeout.push(sec_nonce);
            nonce_sigs.assert_commit_timeout.push(nonce_sig);
            index += 1;
        }
    }
    (pub_nonces, sec_nonces, nonce_sigs)
}

pub fn verify_nonce_signatures(
    pubkey: &XOnlyPublicKey,
    pub_nonces: &CommitteePubNonces,
    nonce_sigs: &CommitteeNonceSignatures,
    watchtower_num: usize,
    assert_commit_num: usize,
) -> Result<bool> {
    pub_nonces.validate_length(watchtower_num, assert_commit_num)?;
    nonce_sigs.validate_length(watchtower_num, assert_commit_num)?;

    fn verify_vec(
        pubkey: &XOnlyPublicKey,
        nonces: &Vec<PubNonce>,
        sigs: &Vec<SchnorrSignature>,
    ) -> bool {
        if nonces.len() != sigs.len() {
            return false;
        }
        nonces.iter().zip(sigs.iter()).all(|(nonce, sig)| verify_public_nonce(sig, nonce, pubkey))
    }

    Ok(verify_vec(pubkey, &pub_nonces.take1, &nonce_sigs.take1)
        && verify_vec(pubkey, &pub_nonces.take2, &nonce_sigs.take2)
        && verify_vec(pubkey, &pub_nonces.challenge, &nonce_sigs.challenge)
        && verify_vec(
            pubkey,
            &pub_nonces.watchtower_challenge_timeout,
            &nonce_sigs.watchtower_challenge_timeout,
        )
        && verify_vec(pubkey, &pub_nonces.nack, &nonce_sigs.nack)
        && verify_vec(
            pubkey,
            &pub_nonces.blockhash_commit_timeout,
            &nonce_sigs.blockhash_commit_timeout,
        )
        && verify_vec(pubkey, &pub_nonces.assert_commit_timeout, &nonce_sigs.assert_commit_timeout))
}

pub(crate) fn generate_nonce(
    signer_keypair: Keypair,
    seed: &str,
    index: usize,
) -> (SecNonce, PubNonce, SchnorrSignature) {
    let nonce_seed = sha256_with_id(seed, index);
    let nonce_seed = <[u8; 32]>::from_hex(&nonce_seed).unwrap();
    let sec_nonce = SecNonce::build(nonce_seed).build();
    let pub_nonce = sec_nonce.public_nonce();
    let nonce_signature = signer_keypair.sign_schnorr(get_nonce_message(&pub_nonce));
    (sec_nonce, pub_nonce, nonce_signature)
}
fn sha256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    format!("{:x}", hasher.finalize())
}
fn sha256_with_id(input: &str, idx: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    sha256(&format!("{:x}{:04x}", hasher.finalize(), idx))
}
