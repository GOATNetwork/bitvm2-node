# `part-stark-vk-attest` CLI Guide

This document explains how to use `part-stark-vk-attest` to build the latest `part_stark_vk` attestation snapshot and add publisher signatures to that snapshot.

## Overview

The CLI currently provides two subcommands:

- `build-tree`
- `sign-root`

The workflow is fixed:

1. Run `build-tree` first to generate the latest snapshot from the full active version set
2. Let each publisher signer run `sign-root` once
3. After the number of signatures in `manifest.json` reaches the threshold from `commit_info`, the proof side can load the attestation snapshot

## Binary Entry

```bash
cargo run -p bitvm2-noded --bin part-stark-vk-attest -- <subcommand> ...
```

The binary is defined in:

- [`node/Cargo.toml`](../node/Cargo.toml)
- [`node/src/bin/part_stark_vk_attest.rs`](../node/src/bin/part_stark_vk_attest.rs)

## Directory Model

The attestation directory stores only one latest snapshot. Historical snapshots are not kept.

Default output directory:

```text
data/psv-attestations
```

Latest snapshot layout:

```text
data/psv-attestations/
  manifest.json
  proofs/
    v1.2.4.json
    v1.2.5.json
```

Where:

- `manifest.json` stores the current Merkle root, ordered versions, publisher metadata, and aggregated signatures
- `proofs/<version>.json` stores the `part_stark_vk`, `leaf_index`, and `merkle_path` for each version

## Version Rules

All `--versions` inputs represent the full active version set, not incremental additions.

The CLI will:

1. Sort versions by semver
2. Load `part_stark_vk` for each sorted version
3. Build the Merkle tree using that sorted order

Example:

```text
Input:  v1.2.10,v1.2.4,v1.2.5
Sorted: v1.2.4,v1.2.5,v1.2.10
```

If versions are duplicated, the command fails.

## `build-tree`

### Purpose

- Build the latest Merkle tree from the full version set
- Generate Merkle proofs for every version
- Overwrite the attestation directory
- Do not write signatures

### Command Format

```bash
cargo run -p bitvm2-noded --bin part-stark-vk-attest -- \
  build-tree \
  --versions <v1,v2,...> \
  --attestation-dir <dir>
```

### Parameters

- `--versions`
  Comma-separated version list
- `--attestation-dir`
  Output attestation directory; defaults to `data/psv-attestations`

### Example

```bash
cargo run -p bitvm2-noded --bin part-stark-vk-attest -- \
  build-tree \
  --versions v1.2.4,v1.2.5 \
  --attestation-dir circuits/data/psv-attestations
```

### Output

On success, the command prints output similar to:

```text
built latest part_stark_vk snapshot in circuits/data/psv-attestations for versions v1.2.4,v1.2.5
```

Note:

- `build-tree` creates an unsigned snapshot
- Running only `build-tree` is not enough for the proof side to consume the attestation

## `sign-root`

### Purpose

- Rebuild the Merkle tree from the same version set
- Load the current publisher set and threshold from `commit_info.active_publisher_set()`
- Sign the current root with a single publisher private key
- Merge the signature into the latest `manifest.json`

### Command Format

```bash
cargo run -p bitvm2-noded --bin part-stark-vk-attest -- \
  sign-root \
  --versions <v1,v2,...> \
  --commit-info-file <file> \
  --publisher-secret-key-wif <publisher_secret_key_wif> \
  --attestation-dir <dir>
```

### Parameters

- `--versions`
  Full active version set; must match the snapshot being signed
- `--commit-info-file`
  Path to `commit_info.json`
- `--publisher-secret-key-wif`
  Bitcoin WIF private key for a single publisher signer
- `--attestation-dir`
  Attestation directory; defaults to `data/psv-attestations`

### Signer Matching Rule

The command does not require a manual signer index.

`--publisher-secret-key-wif` is parsed as WIF, following the same Bitcoin private key format used in `sequencer-set-publish.rs`.

The CLI will:

1. Derive the compressed public key from the private key
2. Read the current active publisher set from `commit_info.active_publisher_set()`
3. Find that public key inside the active publisher set
4. Use the matching position as `signer_pubkey_index`

If the private key does not belong to the current active publisher set, the command fails.

### Your Current `commit_info`

If you are using:

- [`circuits/data/commit-chain/commit_info.json.0`](../circuits/data/commit-chain/commit_info.json.0)

Then the command looks like:

```bash
cargo run -p bitvm2-noded --bin part-stark-vk-attest -- \
  sign-root \
  --versions v1.2.4,v1.2.5 \
  --commit-info-file circuits/data/commit-chain/commit_info.json.0 \
  --publisher-secret-key-wif <publisher_secret_key_wif> \
  --attestation-dir circuits/data/psv-attestations
```

### Multi-Signer Aggregation

`sign-root` handles only one signer per invocation.

If multiple signers exist, run it once per signer:

```bash
cargo run -p bitvm2-noded --bin part-stark-vk-attest -- \
  sign-root \
  --versions v1.2.4,v1.2.5 \
  --commit-info-file circuits/data/commit-chain/commit_info.json.0 \
  --publisher-secret-key-wif <signer_1_secret_key_wif> \
  --attestation-dir circuits/data/psv-attestations

cargo run -p bitvm2-noded --bin part-stark-vk-attest -- \
  sign-root \
  --versions v1.2.4,v1.2.5 \
  --commit-info-file circuits/data/commit-chain/commit_info.json.0 \
  --publisher-secret-key-wif <signer_2_secret_key_wif> \
  --attestation-dir circuits/data/psv-attestations

cargo run -p bitvm2-noded --bin part-stark-vk-attest -- \
  sign-root \
  --versions v1.2.4,v1.2.5 \
  --commit-info-file circuits/data/commit-chain/commit_info.json.0 \
  --publisher-secret-key-wif <signer_3_secret_key_wif> \
  --attestation-dir circuits/data/psv-attestations
```

Signatures are aggregated into the same `manifest.json`.

## Signature Invalidation Rules

Existing signatures are cleared if any of the following changes:

- Version list changes
- Version ordering changes
- Any resolved `part_stark_vk` bytes change
- `root` changes
- `publisher_set_id` changes

Notes:

- `publisher_set_id` already includes `threshold`
- A threshold change therefore appears as a `publisher_set_id` change

## How the Proof Side Uses It

The proof side accepts only the latest snapshot format.

Requirements:

- `manifest.json` must exist in the attestation directory
- Matching `proofs/<version>.json` files must exist
- `manifest.json` must already contain enough valid signatures

If the directory contains only the old `bundles/` files and no `manifest.json`, the proof side fails immediately.

## Recommended Procedure

### Step 1: Build the Latest Snapshot

```bash
cargo run -p bitvm2-noded --bin part-stark-vk-attest -- \
  build-tree \
  --versions v1.2.4,v1.2.5 \
  --attestation-dir circuits/data/psv-attestations
```

### Step 2: Let Each Signer Add One Signature

```bash
cargo run -p bitvm2-noded --bin part-stark-vk-attest -- \
  sign-root \
  --versions v1.2.4,v1.2.5 \
  --commit-info-file circuits/data/commit-chain/commit_info.json.0 \
  --publisher-secret-key-wif <signer_secret_key_wif> \
  --attestation-dir circuits/data/psv-attestations
```

Repeat until the number of signatures reaches the threshold from `commit_info`.

## Common Errors

- `versions is empty`
  No version list was provided
- `duplicate version '...'`
  Duplicate version after normalization
- `failed to load part_stark_vk for version '...'`
  The local verifier cannot resolve that version
- `publisher_secret_key_wif does not belong to active publisher set`
  The provided WIF key does not belong to the current active publisher set
- `missing latest attestation manifest '.../manifest.json'`
  The proof side is loading an attestation directory without a latest snapshot

## Relevant Implementation Files

- [`node/src/bin/part_stark_vk_attest.rs`](../node/src/bin/part_stark_vk_attest.rs)
- [`crates/bitcoin-light-client-circuit/src/attestation.rs`](../crates/bitcoin-light-client-circuit/src/attestation.rs)
