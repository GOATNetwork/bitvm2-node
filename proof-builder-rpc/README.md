# Proof Builder RPC

## Build

```
BITCOIN_NETWORK=testnet4 cargo build -r
```

## Deployment 

The initial arguments are configured in the [proof-build.toml](./proof-builder.toml), otherwise are loaded from the database. 

The field annotation of the configuration can be referred to doc (circuits)[../circuits/README.md].

## Failure recovery

For `long_runing_task_proof`, like header-chain, commit-chain and state-chain proofs, they can be recovered from the database, specially:

* Header-Chain: A new confirmed(>=1) block should wait for number of confirmation blocks before it's included in the proof. If the confirmation number is not enough, just delete the records in the `long_running_task_proof` table, then it will continue the proof generation.

* Commit-Chain: Since the `sequencer-set-publish` is conducted manually, we can enable this once we have a new publish.

Run `GOAT_BLOCK_NUMBER=${The goat block we anchor} bash -x scp.sh` to publish a sequencer set commitment:

```

#!/bin/bash

###
# This is for integration test on Regtest only.
###
set -e
source .env

DIR="$( cd "$( dirname "$0" )" && pwd )"

if [ -f $OUTPUT_FILE ]; then
    cp $OUTPUT_FILE ${OUTPUT_FILE}.bk 
fi 

cargo build -r --bin sequencer-set-publish
export RUST_LOG=info
CMD="../target/release/sequencer-set-publish"

echo -e "recover the publisher set: next_publishers => publishers"
$CMD payfee --total 3

$CMD sign-seq --owner-btc-key-wif $PUBLISHER1 --goat-block-number $GOAT_BLOCK_NUMBER --next-publisher-btc-pubkeys=$PUBLISHER_BTC_PUBKEYS --publisher-btc-pubkeys=$NEXT_PUBLISHER_BTC_PUBKEYS 
$CMD sign-seq --owner-btc-key-wif $PUBLISHER2 --goat-block-number $GOAT_BLOCK_NUMBER --next-publisher-btc-pubkeys=$PUBLISHER_BTC_PUBKEYS --publisher-btc-pubkeys=$NEXT_PUBLISHER_BTC_PUBKEYS 
$CMD sign-seq --owner-btc-key-wif $PUBLISHER3 --goat-block-number $GOAT_BLOCK_NUMBER --next-publisher-btc-pubkeys=$PUBLISHER_BTC_PUBKEYS --publisher-btc-pubkeys=$NEXT_PUBLISHER_BTC_PUBKEYS 

# broadcast publisher changes to Bitcoin
$CMD push-seq --goat-block-number $GOAT_BLOCK_NUMBER --next-publisher-btc-pubkeys=$PUBLISHER_BTC_PUBKEYS --publisher-btc-pubkeys=$NEXT_PUBLISHER_BTC_PUBKEYS  --commit-info="${DIR}/../circuits/data/commit-chain/commit_info.json.latest"

```

* State-Chain:  When we do genesis commitment of the sequencer set, or re-anchor the state chain, we can insert a state-chain record with block_end to 0 in the database.