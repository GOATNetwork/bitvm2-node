# BitVM2 Circuits 

## Preparation

```
mkdir -p data/header-chain
mkdir -p data/commit-chain
mkdir -p data/watchtower
```

if `Network Prover` is used, see [this](https://docs.zkm.io/dev/prover.html#network-prover) for more details.

## Bitcoin Header Chain

```
bash cron-header-chain-proof.sh $start $batch
```

## Cosmos Commit Chain

Prepare the `commit_info.json`, the input data is formated as below.

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
    ]
  }
]
```

* txid: the publisher's commitment transaction of Cosmos sequencer set. 
* threshold: the number of publisher's signature 
* publisher_public_keys: the publisher's compressed public keys

Generate the proof:

```
cd commit-chain-proof/host
//Genesis
RUST_LOG=debug cargo run --package commit-chain-proof --bin commit-chain-proof -r -- --init-input --output-proof "data/commit-chain/commit-proof.bin" --commits data/commit-chain/commits.bin
//Regular proof
RUST_LOG=info cargo run --package commit-chain-proof --bin commit-chain-proof -r -- --input-proof "data/commit-chain/commit-proof.bin" --output-proof "data/commit-chain/commit-proof2.bin" --commit-info ../node/tests_data/commit_info2.json --commits data/commit-chain/commits.bin
```

## Watchtower proof

```
export BITCOIN_NETWORK=regtest
RUST_LOG=info cargo run --package watchtower-proof --bin watchtower-proof -r -- --genesis-sequencer-commit-txid dcadccc909994689e9f3a36c9d349e89f0cb96764f6d8f4d9632e0f76b0ec84e --latest-sequencer-commit-txid dcadccc909994689e9f3a36c9d349e89f0cb96764f6d8f4d9632e0f76b0ec84e --header-chain-input-proof data/header-chain/540100-20000.bin --commit-chain-input-proof data/commit-chain/commit-proof.bin --output "data/watchtower/output.bin" --block-headers data/header-chain/block_headers.bin 

RUST_LOG=debug cargo run --package watchtower-proof --bin watchtower-proof -r -- --genesis-sequencer-commit-txid dcadccc909994689e9f3a36c9d349e89f0cb96764f6d8f4d9632e0f76b0ec84e --latest-sequencer-commit-txid dee4f6e15f40f7efdbf3f6cd5292b02d69a12d7ab7dd476ad71f7bfc1d187584 --header-chain-input-proof data/header-chain/540100-20000.bin --commit-chain-input-proof data/commit-chain/commit-proof2.bin --output "data/watchtower/output2.bin"
```

* latest-sequencer-commit-txid: the latest publisher's commitment Bitcoin transaction id
* header-chain-input-proof: the header chain's proof, input and vk.
* commit-chain-input-proof: the commit chain's proof, input and vk.

## Operator proof

Prepare for the 

```
RUST_BACKTRACE=1 cargo run -r -- --latest-sequencer-commit-txid dee4f6e15f40f7efdbf3f6cd5292b02d69a12d7ab7dd476ad71f7bfc1d187584 --header-chain-input-proof ../../header-chain-proof/host/26700-100.bin --commit-chain-input-proof ../../commit-chain-proof/host/commit-proof2.bin --output "output.bin" --included-watchtowers 1 --execution-layer-block-number 5756299 --watchtower-challenge-info ./watchtower_info.json --watchtower-challenge-init-txid 315edf0312d541f7a27cd342ae632e9419397e3328f61b1dd391dbf3a9ecf19c --consensus-layer-block-number 5756785
```

* latest-sequencer-commit-txid: the latest publisher's commitment Bitcoin transaction id
* header-chain-input-proof: the header chain's proof, input and vk.
* commit-chain-input-proof: the commit chain's proof, input and vk.
* included-watchtower: a 256-bit bitmask; each bit flags a valid watchtower.
* execution-layer-block-number: the block number that including `processWithdraw`(Peg-out) transaction of GOAT Network's execution layer(Geth).
* watchtower-challenge-info: list of watchtower's challenge transaction id and compressed public key.
* watchtower-challenge-init-txid: the watchtower challenge init transaction id in GOAT's BitVM2 graph.

For example.
```
[
    [
        "207012fff4c9fddcbd659db3d36de84a867acb22d163c07ff0f49d699c6d7602",
        "0272efe7ccae21d2541ad85d4f2961f2e5593c29dc8bc37bf87035fc2d5527a651"
    ] 
]
```

* consensus-layer-block-number: the block number that including the latest sequencer set commitment transaction of GOAT Network's consensus layer. 