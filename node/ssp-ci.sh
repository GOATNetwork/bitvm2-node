#!/bin/bash

###
# This is for integration test on Regtest only.
###
set -e
source .env

DIR="$( cd "$( dirname "$0" )" && pwd )"

#GOAT_BLOCK_NUMBER=${1:-9344536}
#GOAT_GENESIS_TXID=""

if [ -f $OUTPUT_FILE ]; then
    mv $OUTPUT_FILE /tmp/ 
fi 

#CMD="cargo run -r --bin sequencer-set-publish --"
cargo build -r
#export RUST_LOG=debug
CMD="../target/release/sequencer-set-publish"

$CMD fund  

# payfee
$CMD payfee --total 5 

echo -e "publish genisis sign sequencer set" 
$CMD push-seq --goat-block-number $GOAT_BLOCK_NUMBER --next-publisher-btc-pubkeys=$PUBLISHER_BTC_PUBKEYS --init-genesis --commit-info="${DIR}/../circuits/data/commit-chain/commit_info.json.0"

echo -e "set the new publisher set: publishers: ${PUBLISHER_BTC_PUBKEYS} => next_publishers: ${NEXT_PUBLISHER_BTC_PUBKEYS}"
$CMD payfee --total 5

$CMD sign-seq --owner-btc-key-wif cMceqPhHedrhbcR9eXgzmfWy7kRqLyAxMYwFT6ABDWsiwUp9Nsq9 --goat-block-number $GOAT_BLOCK_NUMBER
$CMD sign-seq --owner-btc-key-wif cMec2DGaTXkYJYfi7x3ZGjRXkeqmAvYAoWzMAcWj5fdLaqudWsNi --goat-block-number $GOAT_BLOCK_NUMBER
$CMD sign-seq --owner-btc-key-wif cMgZD2qsGReP1UvGbNQ7moL6PZFgzsuPFV3St8sGwpNxED4hqkEM --goat-block-number $GOAT_BLOCK_NUMBER
$CMD sign-seq --owner-btc-key-wif cMiWPrRA5KYDiRAq4nkgGsEf2TfcpqGbhT6YbfDpoy8ZsaAHiDeo --goat-block-number $GOAT_BLOCK_NUMBER
$CMD sign-seq --owner-btc-key-wif cMkTafzStDS4RMRPYD7Emw9DfN5Yendp9R9eKBaNg7tBWwGU43fD --goat-block-number $GOAT_BLOCK_NUMBER

# broadcast publisher changes to Bitcoin
$CMD push-seq --goat-block-number $GOAT_BLOCK_NUMBER --commit-info="${DIR}/../circuits/data/commit-chain/commit_info.json.1"

GOAT_BLOCK_NUMBER=$(($GOAT_BLOCK_NUMBER+1))
echo -e "recover the publisher set: next_publishers => publishers"
$CMD payfee --total 3

$CMD sign-seq --owner-btc-key-wif cMceqPhHedrhbcR9eXgzmfWy7kRqLyAxMYwFT6ABDWsiwUp9Nsq9 --goat-block-number $GOAT_BLOCK_NUMBER --next-publisher-btc-pubkeys=$PUBLISHER_BTC_PUBKEYS --publisher-btc-pubkeys=$NEXT_PUBLISHER_BTC_PUBKEYS
$CMD sign-seq --owner-btc-key-wif cMec2DGaTXkYJYfi7x3ZGjRXkeqmAvYAoWzMAcWj5fdLaqudWsNi --goat-block-number $GOAT_BLOCK_NUMBER --next-publisher-btc-pubkeys=$PUBLISHER_BTC_PUBKEYS --publisher-btc-pubkeys=$NEXT_PUBLISHER_BTC_PUBKEYS
$CMD sign-seq --owner-btc-key-wif cMgZD2qsGReP1UvGbNQ7moL6PZFgzsuPFV3St8sGwpNxED4hqkEM --goat-block-number $GOAT_BLOCK_NUMBER --next-publisher-btc-pubkeys=$PUBLISHER_BTC_PUBKEYS --publisher-btc-pubkeys=$NEXT_PUBLISHER_BTC_PUBKEYS


# broadcast publisher changes to Bitcoin
$CMD push-seq --goat-block-number $GOAT_BLOCK_NUMBER --next-publisher-btc-pubkeys=$PUBLISHER_BTC_PUBKEYS --publisher-btc-pubkeys=$NEXT_PUBLISHER_BTC_PUBKEYS --commit-info="${DIR}/../circuits/data/commit-chain/commit_info.json.2"
