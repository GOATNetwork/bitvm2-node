use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const PART_STARK_VK_TREE_HEIGHT: usize = 6;
pub const PART_STARK_VK_TREE_LEAFS: usize = 1 << PART_STARK_VK_TREE_HEIGHT;
pub const PART_STARK_VK_ROOT_SIGNATURE_DOMAIN: &[u8] = b"bitvm2:part_stark_vk_root:v2";
pub const PART_STARK_VK_PUBLISHER_SET_DOMAIN: &[u8] = b"bitvm2:publisher_set:v1";
pub const PART_STARK_VK_ATTESTATION_DIR_ENV: &str = "PART_STARK_VK_ATTESTATION_DIR";
pub const DEFAULT_PART_STARK_VK_ATTESTATION_DIR: &str = "data/psv-attestations";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartStarkVkRootSignature {
    pub signer_pubkey_index: usize,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartStarkVkAttestationBundle {
    pub part_stark_vk: Vec<u8>,
    pub leaf_index: usize,
    pub merkle_path: Vec<[u8; 32]>,
    pub root: [u8; 32],
    pub threshold: u16,
    pub publisher_set_id: [u8; 32],
    pub signatures: Vec<PartStarkVkRootSignature>,
}

pub type UniquePartStarkVkWitness = PartStarkVkAttestationBundle;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerAttestationInputs {
    pub unique_witnesses: Vec<UniquePartStarkVkWitness>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorAttestationInputs {
    pub unique_witnesses: Vec<UniquePartStarkVkWitness>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartStarkVkTreeState {
    pub tree_height: usize,
    pub leaves: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatestPartStarkVkAttestationManifest {
    pub tree_height: usize,
    pub ordered_versions: Vec<String>,
    pub root: [u8; 32],
    pub threshold: Option<u16>,
    pub publisher_set_id: Option<[u8; 32]>,
    pub publisher_public_keys: Option<Vec<String>>,
    pub signatures: Vec<PartStarkVkRootSignature>,
    pub part_stark_vk_leaf_hashes: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedPartStarkVkMerkleProof {
    pub version: String,
    pub part_stark_vk: Vec<u8>,
    pub leaf_index: usize,
    pub merkle_path: Vec<[u8; 32]>,
}

pub fn part_stark_vk_attestation_dir() -> PathBuf {
    std::env::var(PART_STARK_VK_ATTESTATION_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_PART_STARK_VK_ATTESTATION_DIR))
}

/// Hash the ordered publisher set together with the active threshold.
pub fn compute_publisher_set_id(publisher_public_keys: &[PublicKey], threshold: u16) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(
        PART_STARK_VK_PUBLISHER_SET_DOMAIN.len() + 1 + 2 + 4 + publisher_public_keys.len() * 33,
    );
    bytes.extend_from_slice(PART_STARK_VK_PUBLISHER_SET_DOMAIN);
    bytes.push(0x00);
    bytes.extend_from_slice(&threshold.to_le_bytes());
    bytes.extend_from_slice(&(publisher_public_keys.len() as u32).to_le_bytes());
    for pubkey in publisher_public_keys {
        bytes.extend_from_slice(&pubkey.serialize());
    }

    Sha256::digest(bytes).into()
}

pub fn part_stark_vk_leaf_hash(part_stark_vk: &[u8]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(1 + 4 + part_stark_vk.len());
    bytes.push(0x00);
    bytes.extend_from_slice(&(part_stark_vk.len() as u32).to_le_bytes());
    bytes.extend_from_slice(part_stark_vk);

    Sha256::digest(bytes).into()
}

pub fn part_stark_vk_internal_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(1 + 32 + 32);
    bytes.push(0x01);
    bytes.extend_from_slice(&left);
    bytes.extend_from_slice(&right);

    Sha256::digest(bytes).into()
}

pub fn empty_part_stark_vk_leaf_hash() -> [u8; 32] {
    part_stark_vk_leaf_hash(&[])
}

pub fn part_stark_vk_bundle_id(part_stark_vk: &[u8]) -> String {
    hex::encode(part_stark_vk_leaf_hash(part_stark_vk))
}

pub fn part_stark_vk_tree_state_path(dir: &Path) -> PathBuf {
    dir.join("tree_state.json")
}

pub fn part_stark_vk_bundle_path(dir: &Path, part_stark_vk: &[u8]) -> PathBuf {
    dir.join("bundles").join(format!("{}.json", part_stark_vk_bundle_id(part_stark_vk)))
}

pub fn latest_part_stark_vk_attestation_manifest_path(dir: &Path) -> PathBuf {
    dir.join("manifest.json")
}

pub fn latest_part_stark_vk_attestation_proofs_dir(dir: &Path) -> PathBuf {
    dir.join("proofs")
}

pub fn latest_part_stark_vk_attestation_proof_path(dir: &Path, version: &str) -> PathBuf {
    latest_part_stark_vk_attestation_proofs_dir(dir).join(format!("{version}.json"))
}

fn build_part_stark_vk_leaf_layer(
    part_stark_vks: &[Vec<u8>],
    tree_height: usize,
) -> Result<Vec<[u8; 32]>, String> {
    let total_leafs = 1usize << tree_height;
    if part_stark_vks.len() > total_leafs {
        return Err(format!(
            "too many part_stark_vk leafs: {}, max {}",
            part_stark_vks.len(),
            total_leafs
        ));
    }

    let mut nodes = vec![empty_part_stark_vk_leaf_hash(); total_leafs];
    for (index, part_stark_vk) in part_stark_vks.iter().enumerate() {
        nodes[index] = part_stark_vk_leaf_hash(part_stark_vk);
    }
    Ok(nodes)
}

pub fn build_part_stark_vk_merkle_root(
    part_stark_vks: &[Vec<u8>],
    tree_height: usize,
) -> Result<[u8; 32], String> {
    let mut level = build_part_stark_vk_leaf_layer(part_stark_vks, tree_height)?;
    while level.len() > 1 {
        level = level
            .chunks_exact(2)
            .map(|pair| part_stark_vk_internal_hash(pair[0], pair[1]))
            .collect();
    }
    Ok(level[0])
}

pub fn build_part_stark_vk_merkle_path(
    part_stark_vks: &[Vec<u8>],
    tree_height: usize,
    leaf_index: usize,
) -> Result<Vec<[u8; 32]>, String> {
    let total_leafs = 1usize << tree_height;
    if leaf_index >= total_leafs {
        return Err(format!("leaf index {} out of range {}", leaf_index, total_leafs));
    }

    let mut level = build_part_stark_vk_leaf_layer(part_stark_vks, tree_height)?;
    let mut index = leaf_index;
    let mut path = Vec::with_capacity(tree_height);
    while level.len() > 1 {
        path.push(level[index ^ 1]);
        level = level
            .chunks_exact(2)
            .map(|pair| part_stark_vk_internal_hash(pair[0], pair[1]))
            .collect();
        index /= 2;
    }
    Ok(path)
}

pub fn verify_part_stark_vk_merkle_path(
    part_stark_vk: &[u8],
    leaf_index: usize,
    merkle_path: &[[u8; 32]],
    expected_root: [u8; 32],
    tree_height: usize,
) -> Result<(), String> {
    if merkle_path.len() != tree_height {
        return Err(format!(
            "invalid merkle path length: {}, expected {}",
            merkle_path.len(),
            tree_height
        ));
    }

    let total_leafs = 1usize << tree_height;
    if leaf_index >= total_leafs {
        return Err(format!("leaf index {} out of range {}", leaf_index, total_leafs));
    }

    let mut node = part_stark_vk_leaf_hash(part_stark_vk);
    let mut index = leaf_index;
    for sibling in merkle_path {
        node = if index.is_multiple_of(2) {
            part_stark_vk_internal_hash(node, *sibling)
        } else {
            part_stark_vk_internal_hash(*sibling, node)
        };
        index /= 2;
    }

    if node != expected_root {
        return Err("part_stark_vk merkle root mismatch".to_string());
    }
    Ok(())
}

/// Domain-separate the attestation root by tree height, threshold and publisher set identity.
pub fn build_attestation_message_digest(
    tree_height: usize,
    root: [u8; 32],
    threshold: u16,
    publisher_set_id: [u8; 32],
) -> [u8; 32] {
    let mut bytes =
        Vec::with_capacity(PART_STARK_VK_ROOT_SIGNATURE_DOMAIN.len() + 1 + 1 + 1 + 2 + 32 + 32);
    bytes.extend_from_slice(PART_STARK_VK_ROOT_SIGNATURE_DOMAIN);
    bytes.push(0x00);
    bytes.push(tree_height as u8);
    bytes.push(0x00);
    bytes.extend_from_slice(&threshold.to_le_bytes());
    bytes.extend_from_slice(&publisher_set_id);
    bytes.extend_from_slice(&root);

    Sha256::digest(bytes).into()
}

fn verify_part_stark_vk_root_signatures(
    signatures: &[PartStarkVkRootSignature],
    publisher_public_keys: &[PublicKey],
    threshold: u16,
    tree_height: usize,
    root: [u8; 32],
    publisher_set_id: [u8; 32],
) -> Result<(), String> {
    if publisher_public_keys.is_empty() {
        return Err("publisher_public_keys is empty".to_string());
    }
    let required = usize::from(threshold);
    if required == 0 {
        return Err("threshold must be greater than 0".to_string());
    }
    if required > publisher_public_keys.len() {
        return Err(format!(
            "threshold {} exceeds publisher_public_keys length {}",
            required,
            publisher_public_keys.len()
        ));
    }
    let message = Message::from_digest(build_attestation_message_digest(
        tree_height,
        root,
        threshold,
        publisher_set_id,
    ));
    let secp = Secp256k1::verification_only();
    let mut seen = std::collections::BTreeSet::new();
    let mut valid = 0usize;

    for root_signature in signatures {
        if root_signature.signer_pubkey_index >= publisher_public_keys.len() {
            return Err(format!(
                "signer_pubkey_index {} out of range {}",
                root_signature.signer_pubkey_index,
                publisher_public_keys.len()
            ));
        }
        if !seen.insert(root_signature.signer_pubkey_index) {
            continue;
        }

        let signature = Signature::from_compact(&root_signature.signature)
            .map_err(|err| format!("invalid signature encoding: {err}"))?;
        let mut normalized = signature;
        normalized.normalize_s();
        if normalized != signature {
            return Err("signature is not low-s normalized".to_string());
        }

        secp.verify_ecdsa(
            &message,
            &signature,
            &publisher_public_keys[root_signature.signer_pubkey_index],
        )
        .map_err(|err| format!("invalid publisher root signature: {err}"))?;
        valid += 1;
    }

    if valid < required {
        return Err(format!(
            "not enough valid publisher signatures: got {}, required {}",
            valid, required
        ));
    }
    Ok(())
}

/// Verify that a `part_stark_vk` belongs to the fixed-height history tree and that the root is
/// approved by the current commit-chain publisher set.
pub fn verify_part_stark_vk_attestation(
    bundle: &PartStarkVkAttestationBundle,
    publisher_public_keys: &[PublicKey],
    threshold: u16,
    tree_height: usize,
) -> Result<(), String> {
    if bundle.threshold != threshold {
        return Err(format!(
            "attestation threshold mismatch: bundle {}, expected {}",
            bundle.threshold, threshold
        ));
    }
    let expected_publisher_set_id = compute_publisher_set_id(publisher_public_keys, threshold);
    if bundle.publisher_set_id != expected_publisher_set_id {
        return Err("attestation publisher_set_id mismatch".to_string());
    }
    verify_part_stark_vk_merkle_path(
        &bundle.part_stark_vk,
        bundle.leaf_index,
        &bundle.merkle_path,
        bundle.root,
        tree_height,
    )?;
    verify_part_stark_vk_root_signatures(
        &bundle.signatures,
        publisher_public_keys,
        threshold,
        tree_height,
        bundle.root,
        bundle.publisher_set_id,
    )?;

    Ok(())
}

/// Verify each unique witness once so later lookups can reuse the verified payload.
pub fn verify_unique_part_stark_vk_witnesses(
    unique_witnesses: &[UniquePartStarkVkWitness],
    publisher_public_keys: &[PublicKey],
    threshold: u16,
    tree_height: usize,
) -> Result<(), String> {
    for witness in unique_witnesses {
        verify_part_stark_vk_attestation(witness, publisher_public_keys, threshold, tree_height)?;
    }
    Ok(())
}

/// Check whether a target `part_stark_vk` is present in the verified witness set.
pub fn assert_part_stark_vk_in_verified_witnesses(
    unique_witnesses: &[UniquePartStarkVkWitness],
    expected_part_stark_vk: &[u8],
) -> Result<(), String> {
    if unique_witnesses.iter().any(|witness| witness.part_stark_vk == expected_part_stark_vk) {
        return Ok(());
    }
    Err("part_stark_vk not found in verified witnesses".to_string())
}

pub fn load_part_stark_vk_tree_state(dir: &Path) -> Result<PartStarkVkTreeState, String> {
    let path = part_stark_vk_tree_state_path(dir);
    let bytes = std::fs::read(&path)
        .map_err(|err| format!("failed to read tree state '{}': {err}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|err| format!("failed to decode tree state '{}': {err}", path.display()))
}

fn remove_path_if_exists(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    if path.is_dir() {
        std::fs::remove_dir_all(path)
            .map_err(|err| format!("failed to remove dir '{}': {err}", path.display()))?;
    } else {
        std::fs::remove_file(path)
            .map_err(|err| format!("failed to remove file '{}': {err}", path.display()))?;
    }
    Ok(())
}

/// Build the latest snapshot manifest and per-version merkle proofs from ordered versions.
fn build_latest_part_stark_vk_attestation_snapshot(
    ordered_versions: &[String],
    part_stark_vks: &[Vec<u8>],
    threshold: Option<u16>,
    publisher_set_id: Option<[u8; 32]>,
    publisher_public_keys: Option<Vec<String>>,
    signatures: Vec<PartStarkVkRootSignature>,
) -> Result<(LatestPartStarkVkAttestationManifest, Vec<VersionedPartStarkVkMerkleProof>), String> {
    if ordered_versions.is_empty() {
        return Err("ordered_versions is empty".to_string());
    }
    if ordered_versions.len() != part_stark_vks.len() {
        return Err(format!(
            "ordered_versions length {} does not match part_stark_vks length {}",
            ordered_versions.len(),
            part_stark_vks.len()
        ));
    }

    let root = build_part_stark_vk_merkle_root(part_stark_vks, PART_STARK_VK_TREE_HEIGHT)?;
    let mut part_stark_vk_leaf_hashes = BTreeMap::new();
    let mut proofs = Vec::with_capacity(ordered_versions.len());
    for (leaf_index, (version, part_stark_vk)) in
        ordered_versions.iter().zip(part_stark_vks).enumerate()
    {
        let leaf_hash = part_stark_vk_bundle_id(part_stark_vk);
        if part_stark_vk_leaf_hashes.insert(version.clone(), leaf_hash).is_some() {
            return Err(format!("duplicate ordered version '{version}'"));
        }
        proofs.push(VersionedPartStarkVkMerkleProof {
            version: version.clone(),
            part_stark_vk: part_stark_vk.clone(),
            leaf_index,
            merkle_path: build_part_stark_vk_merkle_path(
                part_stark_vks,
                PART_STARK_VK_TREE_HEIGHT,
                leaf_index,
            )?,
        });
    }

    Ok((
        LatestPartStarkVkAttestationManifest {
            tree_height: PART_STARK_VK_TREE_HEIGHT,
            ordered_versions: ordered_versions.to_vec(),
            root,
            threshold,
            publisher_set_id,
            publisher_public_keys,
            signatures,
            part_stark_vk_leaf_hashes,
        },
        proofs,
    ))
}

/// Rewrite the attestation directory so it only contains the current snapshot files.
fn write_latest_part_stark_vk_attestation_snapshot(
    dir: &Path,
    manifest: &LatestPartStarkVkAttestationManifest,
    proofs: &[VersionedPartStarkVkMerkleProof],
) -> Result<(), String> {
    std::fs::create_dir_all(dir)
        .map_err(|err| format!("failed to create attestation dir '{}': {err}", dir.display()))?;
    remove_path_if_exists(&latest_part_stark_vk_attestation_proofs_dir(dir))?;
    remove_path_if_exists(&dir.join("bundles"))?;
    remove_path_if_exists(&part_stark_vk_tree_state_path(dir))?;
    remove_path_if_exists(&latest_part_stark_vk_attestation_manifest_path(dir))?;

    let proofs_dir = latest_part_stark_vk_attestation_proofs_dir(dir);
    std::fs::create_dir_all(&proofs_dir).map_err(|err| {
        format!("failed to create attestation proofs dir '{}': {err}", proofs_dir.display())
    })?;

    for proof in proofs {
        let path = latest_part_stark_vk_attestation_proof_path(dir, &proof.version);
        let bytes = serde_json::to_vec_pretty(proof)
            .map_err(|err| format!("failed to encode proof '{}': {err}", path.display()))?;
        std::fs::write(&path, bytes)
            .map_err(|err| format!("failed to write proof '{}': {err}", path.display()))?;
    }

    let manifest_path = latest_part_stark_vk_attestation_manifest_path(dir);
    let manifest_bytes = serde_json::to_vec_pretty(manifest).map_err(|err| {
        format!("failed to encode latest attestation manifest '{}': {err}", manifest_path.display())
    })?;
    std::fs::write(&manifest_path, manifest_bytes).map_err(|err| {
        format!("failed to write latest attestation manifest '{}': {err}", manifest_path.display())
    })?;
    Ok(())
}

/// Persist a full latest snapshot, optionally including publisher metadata and signatures.
pub fn save_latest_part_stark_vk_attestation_snapshot(
    dir: &Path,
    ordered_versions: &[String],
    part_stark_vks: &[Vec<u8>],
    threshold: Option<u16>,
    publisher_set_id: Option<[u8; 32]>,
    publisher_public_keys: Option<Vec<PublicKey>>,
    signatures: Vec<PartStarkVkRootSignature>,
) -> Result<(), String> {
    let publisher_public_keys =
        publisher_public_keys.map(|keys| keys.into_iter().map(|key| key.to_string()).collect());
    let (manifest, proofs) = build_latest_part_stark_vk_attestation_snapshot(
        ordered_versions,
        part_stark_vks,
        threshold,
        publisher_set_id,
        publisher_public_keys,
        signatures,
    )?;
    write_latest_part_stark_vk_attestation_snapshot(dir, &manifest, &proofs)
}

/// Load the latest manifest that describes the current attestation snapshot.
pub fn load_latest_part_stark_vk_attestation_manifest(
    dir: &Path,
) -> Result<LatestPartStarkVkAttestationManifest, String> {
    let path = latest_part_stark_vk_attestation_manifest_path(dir);
    let bytes = std::fs::read(&path).map_err(|err| {
        format!("failed to read latest attestation manifest '{}': {err}", path.display())
    })?;
    serde_json::from_slice(&bytes).map_err(|err| {
        format!("failed to decode latest attestation manifest '{}': {err}", path.display())
    })
}

/// Load every version proof referenced by the latest manifest in manifest order.
pub fn load_latest_part_stark_vk_attestation_proofs(
    dir: &Path,
    ordered_versions: &[String],
) -> Result<Vec<VersionedPartStarkVkMerkleProof>, String> {
    let mut proofs = Vec::with_capacity(ordered_versions.len());
    for version in ordered_versions {
        let path = latest_part_stark_vk_attestation_proof_path(dir, version);
        let bytes = std::fs::read(&path).map_err(|err| {
            format!("failed to read attestation proof '{}': {err}", path.display())
        })?;
        let proof: VersionedPartStarkVkMerkleProof =
            serde_json::from_slice(&bytes).map_err(|err| {
                format!("failed to decode attestation proof '{}': {err}", path.display())
            })?;
        proofs.push(proof);
    }
    Ok(proofs)
}

/// Merge one signer into the latest snapshot, resetting signatures when the signing context changes.
pub fn sign_latest_part_stark_vk_snapshot(
    dir: &Path,
    ordered_versions: &[String],
    part_stark_vks: &[Vec<u8>],
    publisher_public_keys: &[PublicKey],
    threshold: u16,
    signer_pubkey_index: usize,
    secret_key: &SecretKey,
) -> Result<LatestPartStarkVkAttestationManifest, String> {
    if publisher_public_keys.is_empty() {
        return Err("publisher_public_keys is empty".to_string());
    }
    let required = usize::from(threshold);
    if required == 0 {
        return Err("threshold must be greater than 0".to_string());
    }
    if required > publisher_public_keys.len() {
        return Err(format!(
            "threshold {} exceeds publisher_public_keys length {}",
            required,
            publisher_public_keys.len()
        ));
    }
    if signer_pubkey_index >= publisher_public_keys.len() {
        return Err(format!(
            "signer_pubkey_index {} out of range {}",
            signer_pubkey_index,
            publisher_public_keys.len()
        ));
    }

    let signer_public_key = PublicKey::from_secret_key(&Secp256k1::new(), secret_key);
    if publisher_public_keys[signer_pubkey_index] != signer_public_key {
        return Err(format!(
            "publisher_secret_key does not match publisher public key at index {}",
            signer_pubkey_index
        ));
    }

    let root = build_part_stark_vk_merkle_root(part_stark_vks, PART_STARK_VK_TREE_HEIGHT)?;
    let publisher_set_id = compute_publisher_set_id(publisher_public_keys, threshold);
    let mut signatures = match load_latest_part_stark_vk_attestation_manifest(dir) {
        Ok(existing)
            if existing.ordered_versions == ordered_versions
                && existing.root == root
                && existing.publisher_set_id == Some(publisher_set_id) =>
        {
            existing.signatures
        }
        _ => Vec::new(),
    };

    let signature = PartStarkVkRootSignature {
        signer_pubkey_index,
        signature: sign_part_stark_vk_root(
            secret_key,
            PART_STARK_VK_TREE_HEIGHT,
            root,
            threshold,
            publisher_set_id,
        ),
    };

    if let Some(existing_signature) =
        signatures.iter_mut().find(|existing| existing.signer_pubkey_index == signer_pubkey_index)
    {
        *existing_signature = signature;
    } else {
        signatures.push(signature);
    }
    signatures.sort_by_key(|existing| existing.signer_pubkey_index);

    save_latest_part_stark_vk_attestation_snapshot(
        dir,
        ordered_versions,
        part_stark_vks,
        Some(threshold),
        Some(publisher_set_id),
        Some(publisher_public_keys.to_vec()),
        signatures,
    )?;
    load_latest_part_stark_vk_attestation_manifest(dir)
}

pub fn save_part_stark_vk_tree_state(
    dir: &Path,
    state: &PartStarkVkTreeState,
) -> Result<(), String> {
    std::fs::create_dir_all(dir)
        .map_err(|err| format!("failed to create attestation dir '{}': {err}", dir.display()))?;
    let path = part_stark_vk_tree_state_path(dir);
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|err| format!("failed to encode tree state '{}': {err}", path.display()))?;
    std::fs::write(&path, bytes)
        .map_err(|err| format!("failed to write tree state '{}': {err}", path.display()))
}

pub fn load_part_stark_vk_attestation_bundle(
    dir: &Path,
    part_stark_vk: &[u8],
) -> Result<PartStarkVkAttestationBundle, String> {
    let path = part_stark_vk_bundle_path(dir, part_stark_vk);
    let bytes = std::fs::read(&path)
        .map_err(|err| format!("failed to read attestation bundle '{}': {err}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|err| format!("failed to decode attestation bundle '{}': {err}", path.display()))
}

pub fn save_part_stark_vk_attestation_bundle(
    dir: &Path,
    bundle: &PartStarkVkAttestationBundle,
) -> Result<(), String> {
    let bundle_dir = dir.join("bundles");
    std::fs::create_dir_all(&bundle_dir).map_err(|err| {
        format!("failed to create attestation bundle dir '{}': {err}", bundle_dir.display())
    })?;
    let path = part_stark_vk_bundle_path(dir, &bundle.part_stark_vk);
    let bytes = serde_json::to_vec_pretty(bundle).map_err(|err| {
        format!("failed to encode attestation bundle '{}': {err}", path.display())
    })?;
    std::fs::write(&path, bytes)
        .map_err(|err| format!("failed to write attestation bundle '{}': {err}", path.display()))
}

pub fn sign_part_stark_vk_root(
    secret_key: &SecretKey,
    tree_height: usize,
    root: [u8; 32],
    threshold: u16,
    publisher_set_id: [u8; 32],
) -> Vec<u8> {
    let secp = Secp256k1::new();
    let message = Message::from_digest(build_attestation_message_digest(
        tree_height,
        root,
        threshold,
        publisher_set_id,
    ));
    let signature = secp.sign_ecdsa(&message, secret_key);
    signature.serialize_compact().to_vec()
}

pub fn build_part_stark_vk_root_signatures(
    signer_secret_keys: &[(usize, &SecretKey)],
    tree_height: usize,
    root: [u8; 32],
    threshold: u16,
    publisher_set_id: [u8; 32],
) -> Result<Vec<PartStarkVkRootSignature>, String> {
    if signer_secret_keys.is_empty() {
        return Err("publisher_secret_keys is empty".to_string());
    }

    let mut seen = BTreeSet::new();
    let mut signatures = Vec::with_capacity(signer_secret_keys.len());
    for (signer_pubkey_index, secret_key) in signer_secret_keys {
        if !seen.insert(*signer_pubkey_index) {
            return Err(format!(
                "duplicate signer_pubkey_index {} in publisher_secret_keys",
                signer_pubkey_index
            ));
        }
        signatures.push(PartStarkVkRootSignature {
            signer_pubkey_index: *signer_pubkey_index,
            signature: sign_part_stark_vk_root(
                secret_key,
                tree_height,
                root,
                threshold,
                publisher_set_id,
            ),
        });
    }

    Ok(signatures)
}

pub fn build_part_stark_vk_attestation_bundle(
    leaves: &[Vec<u8>],
    tree_height: usize,
    leaf_index: usize,
    threshold: u16,
    publisher_set_id: [u8; 32],
    signatures: Vec<PartStarkVkRootSignature>,
) -> Result<PartStarkVkAttestationBundle, String> {
    let part_stark_vk = leaves
        .get(leaf_index)
        .ok_or_else(|| format!("leaf index {} out of range {}", leaf_index, leaves.len()))?
        .clone();
    Ok(PartStarkVkAttestationBundle {
        part_stark_vk,
        leaf_index,
        merkle_path: build_part_stark_vk_merkle_path(leaves, tree_height, leaf_index)?,
        root: build_part_stark_vk_merkle_root(leaves, tree_height)?,
        threshold,
        publisher_set_id,
        signatures,
    })
}

pub fn append_part_stark_vk_and_sign(
    dir: &Path,
    part_stark_vk: Vec<u8>,
    publisher_public_keys: &[PublicKey],
    threshold: u16,
    publisher_secret_keys: &[SecretKey],
) -> Result<PartStarkVkAttestationBundle, String> {
    let indexed_secret_keys =
        publisher_secret_keys.iter().enumerate().collect::<Vec<(usize, &SecretKey)>>();
    append_part_stark_vk_and_sign_with_signers(
        dir,
        part_stark_vk,
        publisher_public_keys,
        threshold,
        &indexed_secret_keys,
    )
}

pub fn append_part_stark_vk_and_sign_with_signers(
    dir: &Path,
    part_stark_vk: Vec<u8>,
    publisher_public_keys: &[PublicKey],
    threshold: u16,
    publisher_secret_keys: &[(usize, &SecretKey)],
) -> Result<PartStarkVkAttestationBundle, String> {
    let mut state = if part_stark_vk_tree_state_path(dir).exists() {
        load_part_stark_vk_tree_state(dir)?
    } else {
        PartStarkVkTreeState { tree_height: PART_STARK_VK_TREE_HEIGHT, leaves: vec![] }
    };
    if state.tree_height != PART_STARK_VK_TREE_HEIGHT {
        return Err(format!(
            "unsupported tree height {}, expected {}",
            state.tree_height, PART_STARK_VK_TREE_HEIGHT
        ));
    }
    if state.leaves.len() >= (1usize << state.tree_height) {
        return Err("part_stark_vk history tree is full".to_string());
    }
    if state.leaves.iter().any(|leaf| leaf == &part_stark_vk) {
        return Err("part_stark_vk already exists in tree".to_string());
    }
    state.leaves.push(part_stark_vk.clone());
    let bundle = resign_part_stark_vk_tree(
        dir,
        &state,
        publisher_public_keys,
        threshold,
        publisher_secret_keys,
        state.leaves.len() - 1,
    )?;
    save_part_stark_vk_tree_state(dir, &state)?;
    Ok(bundle)
}

pub fn resign_current_part_stark_vk_root(
    dir: &Path,
    publisher_public_keys: &[PublicKey],
    threshold: u16,
    publisher_secret_keys: &[SecretKey],
) -> Result<(), String> {
    let indexed_secret_keys =
        publisher_secret_keys.iter().enumerate().collect::<Vec<(usize, &SecretKey)>>();
    resign_current_part_stark_vk_root_with_signers(
        dir,
        publisher_public_keys,
        threshold,
        &indexed_secret_keys,
    )
}

pub fn resign_current_part_stark_vk_root_with_signers(
    dir: &Path,
    publisher_public_keys: &[PublicKey],
    threshold: u16,
    publisher_secret_keys: &[(usize, &SecretKey)],
) -> Result<(), String> {
    let state = load_part_stark_vk_tree_state(dir)?;
    if state.leaves.is_empty() {
        return Err("part_stark_vk tree is empty".to_string());
    }
    for leaf_index in 0..state.leaves.len() {
        let _ = resign_part_stark_vk_tree(
            dir,
            &state,
            publisher_public_keys,
            threshold,
            publisher_secret_keys,
            leaf_index,
        )?;
    }
    Ok(())
}

fn resign_part_stark_vk_tree(
    dir: &Path,
    state: &PartStarkVkTreeState,
    publisher_public_keys: &[PublicKey],
    threshold: u16,
    publisher_secret_keys: &[(usize, &SecretKey)],
    leaf_index: usize,
) -> Result<PartStarkVkAttestationBundle, String> {
    let root = build_part_stark_vk_merkle_root(&state.leaves, state.tree_height)?;
    let publisher_set_id = compute_publisher_set_id(publisher_public_keys, threshold);
    let signatures = build_part_stark_vk_root_signatures(
        publisher_secret_keys,
        state.tree_height,
        root,
        threshold,
        publisher_set_id,
    )?;
    let bundle = build_part_stark_vk_attestation_bundle(
        &state.leaves,
        state.tree_height,
        leaf_index,
        threshold,
        publisher_set_id,
        signatures,
    )?;
    save_part_stark_vk_attestation_bundle(dir, &bundle)?;
    Ok(bundle)
}

pub fn load_unique_part_stark_vk_witnesses(
    dir: &Path,
    part_stark_vks: &[Vec<u8>],
) -> Result<(Vec<UniquePartStarkVkWitness>, Vec<usize>), String> {
    if !latest_part_stark_vk_attestation_manifest_path(dir).exists() {
        return Err(format!(
            "missing latest attestation manifest '{}'",
            latest_part_stark_vk_attestation_manifest_path(dir).display()
        ));
    }

    load_unique_part_stark_vk_witnesses_from_latest_snapshot(dir, part_stark_vks)
}

fn load_unique_part_stark_vk_witnesses_from_latest_snapshot(
    dir: &Path,
    part_stark_vks: &[Vec<u8>],
) -> Result<(Vec<UniquePartStarkVkWitness>, Vec<usize>), String> {
    let manifest = load_latest_part_stark_vk_attestation_manifest(dir)?;
    let threshold = manifest
        .threshold
        .ok_or_else(|| "latest attestation manifest is missing threshold".to_string())?;
    let publisher_set_id = manifest
        .publisher_set_id
        .ok_or_else(|| "latest attestation manifest is missing publisher_set_id".to_string())?;
    let proofs = load_latest_part_stark_vk_attestation_proofs(dir, &manifest.ordered_versions)?;
    let mut available_witnesses = BTreeMap::<Vec<u8>, UniquePartStarkVkWitness>::new();

    for proof in proofs {
        let expected_leaf_hash =
            manifest.part_stark_vk_leaf_hashes.get(&proof.version).ok_or_else(|| {
                format!("missing part_stark_vk leaf hash for version '{}'", proof.version)
            })?;
        let actual_leaf_hash = part_stark_vk_bundle_id(&proof.part_stark_vk);
        if *expected_leaf_hash != actual_leaf_hash {
            return Err(format!(
                "part_stark_vk leaf hash mismatch for version '{}': expected {}, got {}",
                proof.version, expected_leaf_hash, actual_leaf_hash
            ));
        }

        verify_part_stark_vk_merkle_path(
            &proof.part_stark_vk,
            proof.leaf_index,
            &proof.merkle_path,
            manifest.root,
            manifest.tree_height,
        )?;
        available_witnesses.entry(proof.part_stark_vk.clone()).or_insert_with(|| {
            PartStarkVkAttestationBundle {
                part_stark_vk: proof.part_stark_vk,
                leaf_index: proof.leaf_index,
                merkle_path: proof.merkle_path,
                root: manifest.root,
                threshold,
                publisher_set_id,
                signatures: manifest.signatures.clone(),
            }
        });
    }

    let mut unique_witnesses = Vec::new();
    let mut witness_indexes = Vec::with_capacity(part_stark_vks.len());
    let mut seen = BTreeMap::<Vec<u8>, usize>::new();

    for part_stark_vk in part_stark_vks {
        if let Some(index) = seen.get(part_stark_vk) {
            witness_indexes.push(*index);
            continue;
        }
        let bundle = available_witnesses
            .get(part_stark_vk)
            .cloned()
            .ok_or_else(|| "part_stark_vk not found in latest snapshot".to_string())?;
        let index = unique_witnesses.len();
        unique_witnesses.push(bundle);
        seen.insert(part_stark_vk.clone(), index);
        witness_indexes.push(index);
    }

    Ok((unique_witnesses, witness_indexes))
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey, ecdsa::Signature};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        PART_STARK_VK_TREE_HEIGHT, PartStarkVkAttestationBundle, PartStarkVkRootSignature,
        assert_part_stark_vk_in_verified_witnesses, build_attestation_message_digest,
        build_part_stark_vk_merkle_path, build_part_stark_vk_merkle_root,
        build_part_stark_vk_root_signatures, compute_publisher_set_id,
        load_latest_part_stark_vk_attestation_manifest, load_unique_part_stark_vk_witnesses,
        part_stark_vk_leaf_hash, save_latest_part_stark_vk_attestation_snapshot,
        save_part_stark_vk_attestation_bundle, sign_latest_part_stark_vk_snapshot,
        verify_part_stark_vk_attestation, verify_unique_part_stark_vk_witnesses,
    };

    fn sample_part_stark_vk() -> Vec<u8> {
        hex::decode("2000000000000000d157a916a6350249c6e4efd850dcdac3abf5489d36de2d1aa233c9253522871000000000")
            .unwrap()
    }

    fn sample_part_stark_vk_alt() -> Vec<u8> {
        b"alternate-part-stark-vk".to_vec()
    }

    fn sample_publishers() -> (Vec<SecretKey>, Vec<bitcoin::secp256k1::PublicKey>) {
        let secp = Secp256k1::new();
        let secret_keys = vec![
            SecretKey::from_slice(&[1u8; 32]).unwrap(),
            SecretKey::from_slice(&[2u8; 32]).unwrap(),
            SecretKey::from_slice(&[3u8; 32]).unwrap(),
            SecretKey::from_slice(&[4u8; 32]).unwrap(),
        ];
        let publisher_public_keys = secret_keys
            .iter()
            .map(|sk| bitcoin::secp256k1::PublicKey::from_secret_key(&secp, sk))
            .collect::<Vec<_>>();
        (secret_keys, publisher_public_keys)
    }

    fn sample_attestation_bundle(
        leaves: &[Vec<u8>],
        leaf_index: usize,
        threshold: u16,
        publisher_public_keys: &[bitcoin::secp256k1::PublicKey],
        signer_secret_keys: &[SecretKey],
    ) -> PartStarkVkAttestationBundle {
        let root = build_part_stark_vk_merkle_root(leaves, 6).unwrap();
        let publisher_set_id = compute_publisher_set_id(publisher_public_keys, threshold);
        let indexed_secret_keys =
            signer_secret_keys.iter().enumerate().collect::<Vec<(usize, &SecretKey)>>();
        let signatures = build_part_stark_vk_root_signatures(
            &indexed_secret_keys[..usize::from(threshold)],
            6,
            root,
            threshold,
            publisher_set_id,
        )
        .unwrap();

        PartStarkVkAttestationBundle {
            part_stark_vk: leaves[leaf_index].clone(),
            leaf_index,
            merkle_path: build_part_stark_vk_merkle_path(leaves, 6, leaf_index).unwrap(),
            root,
            threshold,
            publisher_set_id,
            signatures,
        }
    }

    fn unique_test_dir(prefix: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("bitvm2-{prefix}-{nanos}"))
    }

    #[test]
    fn test_part_stark_vk_leaf_hash_matches_spec() {
        assert_eq!(
            hex::encode(part_stark_vk_leaf_hash(&[])),
            "8855508aade16ec573d21e6a485dfd0a7624085c1a14b5ecdd6485de0c6839a4"
        );
    }

    #[test]
    fn test_build_part_stark_vk_merkle_root_matches_spec() {
        let leaves = vec![sample_part_stark_vk(), b"hello".to_vec()];

        assert_eq!(
            hex::encode(build_part_stark_vk_merkle_root(&leaves, 6).unwrap()),
            "8a091f11cab951f0c1228a891c902475b84709e568885a45658840e1b88599d4"
        );
    }

    #[test]
    fn test_build_attestation_message_digest_matches_spec() {
        let secp = Secp256k1::new();
        let secret_keys = [
            SecretKey::from_slice(&[1u8; 32]).unwrap(),
            SecretKey::from_slice(&[2u8; 32]).unwrap(),
            SecretKey::from_slice(&[3u8; 32]).unwrap(),
            SecretKey::from_slice(&[4u8; 32]).unwrap(),
        ];
        let publisher_public_keys = secret_keys
            .iter()
            .map(|sk| bitcoin::secp256k1::PublicKey::from_secret_key(&secp, sk))
            .collect::<Vec<_>>();
        let root = hex::decode("8a091f11cab951f0c1228a891c902475b84709e568885a45658840e1b88599d4")
            .unwrap()
            .try_into()
            .unwrap();
        let threshold = 3u16;
        let publisher_set_id = compute_publisher_set_id(&publisher_public_keys, threshold);
        let mut reversed_public_keys = publisher_public_keys.clone();
        reversed_public_keys.reverse();

        assert_ne!(
            build_attestation_message_digest(6, root, threshold, publisher_set_id),
            build_attestation_message_digest(6, root, threshold - 1, publisher_set_id)
        );
        assert_ne!(publisher_set_id, compute_publisher_set_id(&reversed_public_keys, threshold));
    }

    #[test]
    fn test_verify_part_stark_vk_attestation_accepts_quorum_and_ignores_duplicate_signers() {
        let secp = Secp256k1::new();
        let secret_keys = [
            SecretKey::from_slice(&[1u8; 32]).unwrap(),
            SecretKey::from_slice(&[2u8; 32]).unwrap(),
            SecretKey::from_slice(&[3u8; 32]).unwrap(),
            SecretKey::from_slice(&[4u8; 32]).unwrap(),
        ];
        let publisher_public_keys = secret_keys
            .iter()
            .map(|sk| bitcoin::secp256k1::PublicKey::from_secret_key(&secp, sk))
            .collect::<Vec<_>>();

        let part_stark_vk = sample_part_stark_vk();
        let leaves = vec![part_stark_vk.clone()];
        let root = build_part_stark_vk_merkle_root(&leaves, 6).unwrap();
        let threshold = 3u16;
        let publisher_set_id = compute_publisher_set_id(&publisher_public_keys, threshold);
        let digest = build_attestation_message_digest(6, root, threshold, publisher_set_id);
        let message = Message::from_digest(digest);

        let sig0 = secp.sign_ecdsa(&message, &secret_keys[0]);
        let sig1 = secp.sign_ecdsa(&message, &secret_keys[1]);
        let sig2 = secp.sign_ecdsa(&message, &secret_keys[2]);

        let bundle = PartStarkVkAttestationBundle {
            part_stark_vk,
            leaf_index: 0,
            merkle_path: build_part_stark_vk_merkle_path(&leaves, 6, 0).unwrap(),
            root,
            threshold,
            publisher_set_id,
            signatures: vec![
                PartStarkVkRootSignature {
                    signer_pubkey_index: 0,
                    signature: sig0.serialize_compact().to_vec(),
                },
                PartStarkVkRootSignature {
                    signer_pubkey_index: 1,
                    signature: sig1.serialize_compact().to_vec(),
                },
                PartStarkVkRootSignature {
                    signer_pubkey_index: 1,
                    signature: sig1.serialize_compact().to_vec(),
                },
                PartStarkVkRootSignature {
                    signer_pubkey_index: 2,
                    signature: sig2.serialize_compact().to_vec(),
                },
            ],
        };

        assert!(
            verify_part_stark_vk_attestation(&bundle, &publisher_public_keys, threshold, 6).is_ok()
        );
    }

    #[test]
    fn test_verify_part_stark_vk_attestation_rejects_non_member_signer() {
        let secp = Secp256k1::new();
        let secret_keys = [
            SecretKey::from_slice(&[1u8; 32]).unwrap(),
            SecretKey::from_slice(&[2u8; 32]).unwrap(),
            SecretKey::from_slice(&[3u8; 32]).unwrap(),
        ];
        let publisher_public_keys = secret_keys
            .iter()
            .map(|sk| bitcoin::secp256k1::PublicKey::from_secret_key(&secp, sk))
            .collect::<Vec<_>>();

        let outsider = SecretKey::from_slice(&[9u8; 32]).unwrap();
        let part_stark_vk = sample_part_stark_vk();
        let leaves = vec![part_stark_vk.clone()];
        let root = build_part_stark_vk_merkle_root(&leaves, 6).unwrap();
        let threshold = 2u16;
        let publisher_set_id = compute_publisher_set_id(&publisher_public_keys, threshold);
        let digest = build_attestation_message_digest(6, root, threshold, publisher_set_id);
        let message = Message::from_digest(digest);
        let outsider_sig: Signature = secp.sign_ecdsa(&message, &outsider);

        let bundle = PartStarkVkAttestationBundle {
            part_stark_vk,
            leaf_index: 0,
            merkle_path: build_part_stark_vk_merkle_path(&leaves, 6, 0).unwrap(),
            root,
            threshold,
            publisher_set_id,
            signatures: vec![PartStarkVkRootSignature {
                signer_pubkey_index: 0,
                signature: outsider_sig.serialize_compact().to_vec(),
            }],
        };

        assert!(
            verify_part_stark_vk_attestation(&bundle, &publisher_public_keys, threshold, 6)
                .is_err()
        );
    }

    #[test]
    fn test_build_part_stark_vk_root_signatures_supports_sparse_signer_indexes() {
        let secp = Secp256k1::new();
        let secret_keys = [
            SecretKey::from_slice(&[1u8; 32]).unwrap(),
            SecretKey::from_slice(&[2u8; 32]).unwrap(),
            SecretKey::from_slice(&[3u8; 32]).unwrap(),
            SecretKey::from_slice(&[4u8; 32]).unwrap(),
            SecretKey::from_slice(&[5u8; 32]).unwrap(),
        ];
        let publisher_public_keys = secret_keys
            .iter()
            .map(|sk| bitcoin::secp256k1::PublicKey::from_secret_key(&secp, sk))
            .collect::<Vec<_>>();

        let leaves = vec![sample_part_stark_vk()];
        let root = build_part_stark_vk_merkle_root(&leaves, 6).unwrap();
        let threshold = 4u16;
        let publisher_set_id = compute_publisher_set_id(&publisher_public_keys, threshold);
        let signatures = build_part_stark_vk_root_signatures(
            &[
                (0, &secret_keys[0]),
                (2, &secret_keys[2]),
                (3, &secret_keys[3]),
                (4, &secret_keys[4]),
            ],
            6,
            root,
            threshold,
            publisher_set_id,
        )
        .unwrap();

        let bundle = PartStarkVkAttestationBundle {
            part_stark_vk: leaves[0].clone(),
            leaf_index: 0,
            merkle_path: build_part_stark_vk_merkle_path(&leaves, 6, 0).unwrap(),
            root,
            threshold,
            publisher_set_id,
            signatures,
        };

        assert!(
            verify_part_stark_vk_attestation(&bundle, &publisher_public_keys, threshold, 6).is_ok()
        );
    }

    #[test]
    fn test_verify_part_stark_vk_attestation_rejects_threshold_mismatch() {
        let secp = Secp256k1::new();
        let secret_keys = [
            SecretKey::from_slice(&[1u8; 32]).unwrap(),
            SecretKey::from_slice(&[2u8; 32]).unwrap(),
            SecretKey::from_slice(&[3u8; 32]).unwrap(),
            SecretKey::from_slice(&[4u8; 32]).unwrap(),
        ];
        let publisher_public_keys = secret_keys
            .iter()
            .map(|sk| bitcoin::secp256k1::PublicKey::from_secret_key(&secp, sk))
            .collect::<Vec<_>>();
        let leaves = vec![sample_part_stark_vk()];
        let root = build_part_stark_vk_merkle_root(&leaves, 6).unwrap();
        let signed_threshold = 3u16;
        let publisher_set_id = compute_publisher_set_id(&publisher_public_keys, signed_threshold);
        let signatures = build_part_stark_vk_root_signatures(
            &[(0, &secret_keys[0]), (1, &secret_keys[1]), (2, &secret_keys[2])],
            6,
            root,
            signed_threshold,
            publisher_set_id,
        )
        .unwrap();

        let bundle = PartStarkVkAttestationBundle {
            part_stark_vk: leaves[0].clone(),
            leaf_index: 0,
            merkle_path: build_part_stark_vk_merkle_path(&leaves, 6, 0).unwrap(),
            root,
            threshold: signed_threshold,
            publisher_set_id,
            signatures,
        };

        assert!(
            verify_part_stark_vk_attestation(
                &bundle,
                &publisher_public_keys,
                signed_threshold - 1,
                6
            )
            .is_err()
        );
    }

    #[test]
    fn test_verify_unique_part_stark_vk_witnesses_accepts_multiple_bundles() {
        let (secret_keys, publisher_public_keys) = sample_publishers();
        let leaves = vec![sample_part_stark_vk(), sample_part_stark_vk_alt()];
        let unique_witnesses = vec![
            sample_attestation_bundle(&leaves, 0, 3, &publisher_public_keys, &secret_keys),
            sample_attestation_bundle(&leaves, 1, 3, &publisher_public_keys, &secret_keys),
        ];

        assert!(
            verify_unique_part_stark_vk_witnesses(&unique_witnesses, &publisher_public_keys, 3, 6)
                .is_ok()
        );
    }

    #[test]
    fn test_assert_part_stark_vk_in_verified_witnesses_checks_membership() {
        let (secret_keys, publisher_public_keys) = sample_publishers();
        let leaves = vec![sample_part_stark_vk(), sample_part_stark_vk_alt()];
        let unique_witnesses = vec![
            sample_attestation_bundle(&leaves, 0, 3, &publisher_public_keys, &secret_keys),
            sample_attestation_bundle(&leaves, 1, 3, &publisher_public_keys, &secret_keys),
        ];

        verify_unique_part_stark_vk_witnesses(&unique_witnesses, &publisher_public_keys, 3, 6)
            .unwrap();
        assert!(assert_part_stark_vk_in_verified_witnesses(&unique_witnesses, &leaves[1]).is_ok());
        assert!(
            assert_part_stark_vk_in_verified_witnesses(&unique_witnesses, b"missing-part-stark-vk")
                .is_err()
        );
    }

    #[test]
    fn test_load_unique_part_stark_vk_witnesses_reuses_duplicate_indexes_from_latest_snapshot() {
        let (secret_keys, publisher_public_keys) = sample_publishers();
        let leaves = vec![sample_part_stark_vk(), sample_part_stark_vk_alt()];
        let dir = unique_test_dir("attestation-duplicate-indexes");
        let ordered_versions = vec!["v1.2.4".to_string(), "v1.2.5".to_string()];
        let threshold = 3;
        let publisher_set_id = compute_publisher_set_id(&publisher_public_keys, threshold);
        let signatures = build_part_stark_vk_root_signatures(
            &[(0, &secret_keys[0]), (1, &secret_keys[1]), (2, &secret_keys[2])],
            PART_STARK_VK_TREE_HEIGHT,
            build_part_stark_vk_merkle_root(&leaves, PART_STARK_VK_TREE_HEIGHT).unwrap(),
            threshold,
            publisher_set_id,
        )
        .unwrap();

        save_latest_part_stark_vk_attestation_snapshot(
            &dir,
            &ordered_versions,
            &leaves,
            Some(threshold),
            Some(publisher_set_id),
            Some(publisher_public_keys.clone()),
            signatures,
        )
        .unwrap();

        let requested = vec![leaves[0].clone(), leaves[1].clone(), leaves[0].clone()];
        let (unique_witnesses, witness_indexes) =
            load_unique_part_stark_vk_witnesses(&dir, &requested).unwrap();

        assert_eq!(unique_witnesses.len(), 2);
        assert_eq!(witness_indexes, vec![0, 1, 0]);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_load_unique_part_stark_vk_witnesses_requires_latest_manifest() {
        let (secret_keys, publisher_public_keys) = sample_publishers();
        let leaves = vec![sample_part_stark_vk(), sample_part_stark_vk_alt()];
        let dir = unique_test_dir("attestation-requires-latest-manifest");
        std::fs::create_dir_all(dir.join("bundles")).unwrap();

        let first_bundle =
            sample_attestation_bundle(&leaves, 0, 3, &publisher_public_keys, &secret_keys);
        save_part_stark_vk_attestation_bundle(&dir, &first_bundle).unwrap();

        let err = load_unique_part_stark_vk_witnesses(&dir, &[leaves[0].clone()]).unwrap_err();
        assert!(err.contains("missing latest attestation manifest"));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_save_and_load_latest_snapshot_reuses_duplicate_indexes() {
        let (secret_keys, publisher_public_keys) = sample_publishers();
        let leaves = vec![sample_part_stark_vk(), sample_part_stark_vk_alt()];
        let ordered_versions = vec!["v1.2.4".to_string(), "v1.2.5".to_string()];
        let dir = unique_test_dir("latest-attestation-snapshot");
        let threshold = 3;
        let publisher_set_id = compute_publisher_set_id(&publisher_public_keys, threshold);
        let signatures = build_part_stark_vk_root_signatures(
            &[(0, &secret_keys[0]), (1, &secret_keys[1]), (2, &secret_keys[2])],
            PART_STARK_VK_TREE_HEIGHT,
            build_part_stark_vk_merkle_root(&leaves, PART_STARK_VK_TREE_HEIGHT).unwrap(),
            threshold,
            publisher_set_id,
        )
        .unwrap();

        save_latest_part_stark_vk_attestation_snapshot(
            &dir,
            &ordered_versions,
            &leaves,
            Some(threshold),
            Some(publisher_set_id),
            Some(publisher_public_keys.clone()),
            signatures,
        )
        .unwrap();

        let requested = vec![leaves[0].clone(), leaves[1].clone(), leaves[0].clone()];
        let (unique_witnesses, witness_indexes) =
            load_unique_part_stark_vk_witnesses(&dir, &requested).unwrap();

        assert_eq!(unique_witnesses.len(), 2);
        assert_eq!(witness_indexes, vec![0, 1, 0]);
        assert_eq!(unique_witnesses[0].part_stark_vk, leaves[0]);
        assert_eq!(unique_witnesses[1].part_stark_vk, leaves[1]);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_sign_latest_snapshot_preserves_existing_signatures_for_same_identity() {
        let (secret_keys, publisher_public_keys) = sample_publishers();
        let leaves = vec![sample_part_stark_vk(), sample_part_stark_vk_alt()];
        let ordered_versions = vec!["v1.2.4".to_string(), "v1.2.5".to_string()];
        let dir = unique_test_dir("latest-attestation-signatures");

        sign_latest_part_stark_vk_snapshot(
            &dir,
            &ordered_versions,
            &leaves,
            &publisher_public_keys,
            3,
            0,
            &secret_keys[0],
        )
        .unwrap();
        let first_manifest = load_latest_part_stark_vk_attestation_manifest(&dir).unwrap();
        assert_eq!(first_manifest.signatures.len(), 1);

        sign_latest_part_stark_vk_snapshot(
            &dir,
            &ordered_versions,
            &leaves,
            &publisher_public_keys,
            3,
            2,
            &secret_keys[2],
        )
        .unwrap();
        let second_manifest = load_latest_part_stark_vk_attestation_manifest(&dir).unwrap();
        assert_eq!(second_manifest.signatures.len(), 2);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_sign_latest_snapshot_clears_stale_signatures_when_publisher_set_changes() {
        let (secret_keys, publisher_public_keys) = sample_publishers();
        let leaves = vec![sample_part_stark_vk(), sample_part_stark_vk_alt()];
        let ordered_versions = vec!["v1.2.4".to_string(), "v1.2.5".to_string()];
        let dir = unique_test_dir("latest-attestation-publisher-reset");

        sign_latest_part_stark_vk_snapshot(
            &dir,
            &ordered_versions,
            &leaves,
            &publisher_public_keys,
            3,
            0,
            &secret_keys[0],
        )
        .unwrap();
        sign_latest_part_stark_vk_snapshot(
            &dir,
            &ordered_versions,
            &leaves,
            &publisher_public_keys,
            3,
            1,
            &secret_keys[1],
        )
        .unwrap();

        let reordered_publisher_public_keys = vec![
            publisher_public_keys[1],
            publisher_public_keys[0],
            publisher_public_keys[2],
            publisher_public_keys[3],
        ];
        sign_latest_part_stark_vk_snapshot(
            &dir,
            &ordered_versions,
            &leaves,
            &reordered_publisher_public_keys,
            3,
            0,
            &secret_keys[1],
        )
        .unwrap();

        let manifest = load_latest_part_stark_vk_attestation_manifest(&dir).unwrap();
        assert_eq!(manifest.signatures.len(), 1);
        assert_eq!(manifest.signatures[0].signer_pubkey_index, 0);

        std::fs::remove_dir_all(dir).unwrap();
    }
}
