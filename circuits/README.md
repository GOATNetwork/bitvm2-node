# BitVM2 Circuits 

## Verification Path

Trust Setup: choose a snapshot of GOAT Pre Alpha Mainnet, which consists of (Seqeuncer Set, EVM Block Hash)

Verify:

* BTC Header Chain, check whether the Sequencer Set Commitment transaction is in the longgest chain
* Sequencer Set Commitment, check whether the publishers have published the correct Sequencer Set
* State Chain, check the EVM state transition, and check whether the EVM block has been signed by the Sequencer Set
* Operator's total work >= Watchtowers' largest total work

## Preparation

```
mkdir -p data/header-chain
mkdir -p data/commit-chain
mkdir -p data/state-chain
mkdir -p data/watchtower
mkdir -p data/operator
```

if `Network Prover` is used, see [this](https://docs.zkm.io/dev/prover.html#network-prover) for more details.

Launch the Regtest.

```bash
cd scripts
docker compose up -d
```

## Bitcoin Header Chain

```
bash cron-header-chain-proof.sh $start $batch
```

## Sequencer Set Commit Chain

* Publish sequencer set commitment

```bash
cd node
export GOAT_BLOCK_NUMBER=9511050
bash -x ssp-ci.sh $GOAT_BLOCK_NUMBER
```
All the initial publishers are hardcoded. In the `ssp-ci.sh`, we simutate 2-round publisher rotations.
`GOAT_BLOCK_NUMBER` is the GOAT's current block number, which is used as the key to fetch sequencer set commitment.

Note that we should deploy [SequencerSetPublisher Contract](https://github.com/GOATNetwork/bitvm2-L2-contracts/tree/main/script#deploy) before publishing the sequencer set.

Then setup the correct contract address in your `.env`.

```
GOAT_SEQUENCER_SET_PUBLISHER_CONTRACT_ADDRESS=0x...
ENV_GOAT_SEQUENCER_SET_MULTI_SIG_VERIFIER_ADDRESS=0x...
```

After publishing, a `commit_info.json` of format as below will be generated.

```
[
  {
    "txid": "dcadccc909994689e9f3a36c9d349e89f0cb96764f6d8f4d9632e0f76b0ec84e",
    "threshold": 4,
    "publisher_public_keys": [
      "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
      "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766",
      "02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337",
      "03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b",
      "0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7"
    ],
    "sequencers": [...]
  }
]
```

* txid: the publisher's commitment transaction of Cosmos sequencer set. 
* threshold: the number of publisher's signature 
* publisher_public_keys: the publisher's compressed public keys
* sequencers: sequencer's public keys, obtained from cosmos's `/validators`.

Generate the proof:

```
# Genesis
RUST_LOG=info cargo run --package commit-chain-proof --bin commit-chain-proof -r -- --init-input --output-proof "data/commit-chain/commit-proof.bin" --commits data/commit-chain/commits.bin --commit-info ../node/tests_data/commit_info.json

# Regular proof
RUST_LOG=info cargo run --package commit-chain-proof --bin commit-chain-proof -r -- --input-proof "data/commit-chain/commit-proof.bin" --output-proof "data/commit-chain/commit-proof2.bin" --commit-info ../node/tests_data/commit_info2.json --commits data/commit-chain/commits.bin

RUST_LOG=info cargo run --package commit-chain-proof --bin commit-chain-proof -r -- --input-proof "data/commit-chain/commit-proof2.bin" --output-proof "data/commit-chain/commit-proof3.bin" --commit-info ../node/tests_data/commit_info3.json --commits data/commit-chain/commits.bin
```

## State Chain

State Chain represents the L2's state transition, which checks the EVM's execution, withdrawal transaction inclusion and sequencers' aggrement.

We generate `state-chain-proof` periodically, like by 5 GOAT EVM blocks. Optionally, the block may contain a `proceedWithdraw` transaction.

* Submit the `proceedWithdraw` transaction on GOAT Network.
* Generate state-chain proof. If there are some `proceedWithdraw` transactions, configure `GRAPH_IDS` and `GRAPH_BLOCK_NUMBERS` by sparating them by comma. 

```
# Required if applied
export GRAPH_IDS="0x00112233445566778899aabbccddeeff"
export GRAPH_BLOCK_NUMBERS=9511055

export EL_START_BLOCK_NUMBER=9511050
export BATCH_SIZE=10
export L2_CONTRACT_ADDRESS=0x21f619040AC2eAcacEF8Fe17Ae8bDF53ec69C66f

export start=$EL_START_BLOCK_NUMBER
bash cron-state-chain-proof.sh $start $BATCH_SIZE
```

## Watchtower proof

If a challenge is happened, each watchtower should broadcast a `watchtower-challenge-tx` to submit its longest chain.

* Generate proofs

```
export BITCOIN_NETWORK=regtest
export GENESIS_SEQUENCER_COMMIT_TXID=$(cat ../node/tests_data/commit_info.json | jq -r .genesis_txid)
export LATEST_SEQUENCER_COMMIT_TXID=$(cat ../node/tests_data/commit_info.json | jq -r .txid)
export HEADER_CHAIN_INPUT_PROOF="data/header-chain/503050-10.bin"
export COMMIT_CHAIN_INPUT_PROOF="data/commit-chain/commit-proof.bin"
export LATEST_STATE_BLOCK_HASH="0x7908184bce067fa5a4508d309cbaf22dd1e0b586ad2dd42c0e51a5308a7bd815"
export STATE_CHAIN_INPUT_PROOF="data/state-chain/9511050-10.bin"

# optional
export GRAPH_IDS="0x00112233445566778899aabbccddeeff"
export GRAPH_BLOCK_NUMBERS=9511055

RUST_LOG=info cargo run --package watchtower-proof --bin watchtower-proof -r -- --output "data/watchtower/output.bin" --block-headers data/header-chain/block_headers.bin

export LATEST_SEQUENCER_COMMIT_TXID=$(cat ../node/tests_data/commit_info2.json | jq -r .txid)
export COMMIT_CHAIN_INPUT_PROOF="data/commit-chain/commit-proof2.bin"
RUST_LOG=info cargo run --package watchtower-proof --bin watchtower-proof -r -- --output "data/watchtower/output2.bin"

export LATEST_SEQUENCER_COMMIT_TXID=$(cat ../node/tests_data/commit_info3.json | jq -r .txid)
export COMMIT_CHAIN_INPUT_PROOF="data/commit-chain/commit-proof3.bin"
RUST_LOG=info cargo run --package watchtower-proof --bin watchtower-proof -r -- --output "data/watchtower/output3.bin"
```

* latest-sequencer-commit-txid: the latest publisher's commitment Bitcoin transaction id
* header-chain-input-proof: the header chain's proof, input and vk.
* commit-chain-input-proof: the commit chain's proof, input and vk.

## Operator proof

* Simutate a withdraw challenge

```bash
cd crates/bitvm2-ga
cargo test -r test_take2
```
Make sure the operator has enough balance, if not, run this command to fund the operator.

```
bitcoin-cli -regtest -rpcuser=$... -rpcpassword=$... sendtoaddress bcrt1qhnmlpxyxdntekge4u24m4a7yk6elc3zs4v89e7fqja8vagfnrs8sq28cwd 50
```

Get the withdraw-challenge-init-txid , graph-id, watchtower's challenge transaction id and compressed public key.

* Generate proofs

After calling the [`proceedWithdraw`](https://github.com/GOATNetwork/bitvm2-L2-contracts/blob/main/src/Gateway.sol#L588), we generate the operator proof with corresponding `graph_id` and transaction id. 

```
export BITCOIN_NETWORK=regtest
export GENESIS_SEQUENCER_COMMIT_TXID=$(cat ../node/tests_data/commit_info.json | jq -r .genesis_txid)
export LATEST_SEQUENCER_COMMIT_TXID=$(cat ../node/tests_data/commit_info3.json | jq -r .txid)
export HEADER_CHAIN_INPUT_PROOF="data/header-chain/503050-10.bin"
export COMMIT_CHAIN_INPUT_PROOF="data/commit-chain/commit-proof3.bin"
export STATE_CHAIN_INPUT_PROOF="data/state-chain/9511050-10.bin"
export LATEST_STATE_BLOCK_HASH="0x7908184bce067fa5a4508d309cbaf22dd1e0b586ad2dd42c0e51a5308a7bd815"

export GRAPH_ID="0x00112233445566778899aabbccddeeff"
export EXECUTION_LAYER_BLOCK_NUMBER=8447360

export INCLUDED_WATCHTOWERS=1
export WATCHTOWER_PUBLIC_KEYS="0272efe7ccae21d2541ad85d4f2961f2e5593c29dc8bc37bf87035fc2d5527a651"
export WATCHTOWER_CHALLENGE_TXIDS="3b155884a7f6dd65836045779c6cb5e0ebe11d4630f825fb45682b8cef1c79f0"
export WATCHTOWER_CHALLENGE_INIT_TXID="7f7b4344adb1b8937ddb7124e4f8bba80ee9adf5e8119de76ca8736816bda246"


# required 
export GRAPH_IDS="0x00112233445566778899aabbccddeeff"
export GRAPH_BLOCK_NUMBERS=9511055

RUST_LOG=info cargo run --package operator-proof --bin operator-proof -r -- --output "data/operator-proof/output.bin"
```

* latest-sequencer-commit-txid: the latest publisher's commitment Bitcoin transaction id
* header-chain-input-proof: the header chain's proof, input and vk.
* commit-chain-input-proof: the commit chain's proof, input and vk.
* included-watchtower: a 256-bit bitmask; each bit flags a valid watchtower.
* execution-layer-block-number: the block number that including `proceedWithdraw`(Peg-out) transaction of GOAT Network's execution layer(Geth).
* watchtower-challenge-info: list of watchtower's challenge transaction id and compressed public key, i.e: [wachtower_info.json](./data/watchtower/watchtower_info.json).
* watchtower-challenge-init-txid: the watchtower challenge init transaction id in GOAT's BitVM2 graph.