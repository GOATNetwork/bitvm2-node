# Proof Builder RPC

## Build

Use the following command to build the project:

```
BITCOIN_NETWORK=testnet4 cargo build -r
```

## Deployment

Initial parameters are read from `proof-builder.toml` (see [proof-builder.toml](./proof-builder.toml)). After that, they will be loaded from the database.

Field descriptions for the configuration are available in the circuits documentation: [circuits README](../circuits/README.md).

## Failure recovery

Long-running proof tasks (stored in the `long_running_task_proof` table) — such as header-chain, commit-chain, and state-chain proofs — can be recovered from the database. Recovery notes:

- **Header Chain**: A newly confirmed block (>=1) must wait for the configured number of confirmations before being included in a proof. If the confirmation count is insufficient, delete the corresponding entries from the `long_running_task_proof` table; proof generation will resume from the database state.

- **Commit Chain**: The `sequencer-set-publish` process is manual. When a new publish is required, run the publication script with the appropriate `GOAT_BLOCK_NUMBER` to create a sequencer-set commitment. Example invocation:

```bash
GOAT_BLOCK_NUMBER=${THE_GOAT_BLOCK_NUMBER} bash -x scp.sh
```

Example `scp.sh` used for Regtest integration tests:

```bash
#!/bin/bash
set -e
source .env

DIR="$( cd "$( dirname "$0" )" && pwd )"

if [ -f $OUTPUT_FILE ]; then
    cp $OUTPUT_FILE ${OUTPUT_FILE}.bk 
fi 

cargo build -r --bin sequencer-set-publish
export RUST_LOG=info
CMD="../target/release/sequencer-set-publish"

echo "Recovering publisher set: next_publishers => publishers"
$CMD payfee --total 3

$CMD sign-seq --owner-btc-key-wif $PUBLISHER1 --goat-block-number $GOAT_BLOCK_NUMBER \ --next-publisher-btc-pubkeys=$PUBLISHER_BTC_PUBKEYS --publisher-btc-pubkeys=$NEXT_PUBLISHER_BTC_PUBKEYS 
$CMD sign-seq --owner-btc-key-wif $PUBLISHER2 --goat-block-number $GOAT_BLOCK_NUMBER \ --next-publisher-btc-pubkeys=$PUBLISHER_BTC_PUBKEYS --publisher-btc-pubkeys=$NEXT_PUBLISHER_BTC_PUBKEYS 
$CMD sign-seq --owner-btc-key-wif $PUBLISHER3 --goat-block-number $GOAT_BLOCK_NUMBER \ --next-publisher-btc-pubkeys=$PUBLISHER_BTC_PUBKEYS --publisher-btc-pubkeys=$NEXT_PUBLISHER_BTC_PUBKEYS 

# broadcast publisher changes to Bitcoin
$CMD push-seq --goat-block-number $GOAT_BLOCK_NUMBER --next-publisher-btc-pubkeys=$PUBLISHER_BTC_PUBKEYS --publisher-btc-pubkeys=$NEXT_PUBLISHER_BTC_PUBKEYS  --commit-info="${DIR}/../circuits/data/commit-chain/commit_info.json.latest"
```

- **State Chain**: For sequencer-set genesis commitments or when re-anchoring the state chain, modify the latest record of state chain in `long_running_task_proof` with `block_end = 0` and `proof_state = 'Failed'` to trigger recovery handling.