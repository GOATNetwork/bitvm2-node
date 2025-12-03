set -e
source .env

GOAT_BLOCK_NUMBER=${1:-9344536}
GOAT_GENESIS_TXID=""

if [ -f $OUTPUT_FILE ]; then
    mv $OUTPUT_FILE /tmp/ 
fi 

#CMD="cargo run -r --bin sequencer-set-publish --"
cargo build -r
#export RUST_LOG=debug
CMD="../target/release/sequencer-set-publish"

$CMD fund  

# payfee
$CMD payfee

echo -e "publish genisis sign sequencer set" 
$CMD push-seq --goat-block-number $GOAT_BLOCK_NUMBER --next-publishers=$PUBLISHERS

echo -e "set the new publisher set: publishers => next_publishers"
GOAT_BLOCK_NUMBER=$(($GOAT_BLOCK_NUMBER+1))
$CMD payfee

$CMD sign-seq --owner-btc-key-wif cMec2DGaTXkYJYfi7x3ZGjRXkeqmAvYAoWzMAcWj5fdLaqudWsNi --goat-block-number $GOAT_BLOCK_NUMBER
$CMD sign-seq --owner-btc-key-wif cMgZD2qsGReP1UvGbNQ7moL6PZFgzsuPFV3St8sGwpNxED4hqkEM --goat-block-number $GOAT_BLOCK_NUMBER
$CMD sign-seq --owner-btc-key-wif cMiWPrRA5KYDiRAq4nkgGsEf2TfcpqGbhT6YbfDpoy8ZsaAHiDeo --goat-block-number $GOAT_BLOCK_NUMBER

# submit update-seq-set to GOAT
$CMD --goat-evm-prvkey 0xbb094981331d23f14f6fec3749c2bc6effa582d52a0c92c6b257809d89d37ab6 update-seq-set --goat-block-number $GOAT_BLOCK_NUMBER 
$CMD --goat-evm-prvkey 0x134e45328c0cf16fa450e9b40c34cba16a7eac2001b907f1de6a28549776f93e update-seq-set --goat-block-number $GOAT_BLOCK_NUMBER 
$CMD --goat-evm-prvkey 0xe079ee9ddc9440df0e55ca9966b87cdf145dad8cd04a7d6795f80a37a6130305 update-seq-set --goat-block-number $GOAT_BLOCK_NUMBER 
$CMD --goat-evm-prvkey 0xc12bb8b3c48eb1ffd8f573dd9a7da45b06b739a647f5ee60a8a91430a102fbf7 update-seq-set --goat-block-number $GOAT_BLOCK_NUMBER 

# sign offchain 
$CMD --goat-evm-prvkey 0xbb094981331d23f14f6fec3749c2bc6effa582d52a0c92c6b257809d89d37ab6 sign-pub
$CMD --goat-evm-prvkey 0x134e45328c0cf16fa450e9b40c34cba16a7eac2001b907f1de6a28549776f93e sign-pub
$CMD --goat-evm-prvkey 0xe079ee9ddc9440df0e55ca9966b87cdf145dad8cd04a7d6795f80a37a6130305 sign-pub
$CMD --goat-evm-prvkey 0xc12bb8b3c48eb1ffd8f573dd9a7da45b06b739a647f5ee60a8a91430a102fbf7 sign-pub

# update publisher on GOAT
$CMD push-pub --goat-block-number $GOAT_BLOCK_NUMBER

# broadcast publisher changes to Bitcoin
$CMD push-seq --goat-block-number $GOAT_BLOCK_NUMBER

GOAT_BLOCK_NUMBER=$(($GOAT_BLOCK_NUMBER+1))
echo -e "recover the publisher set: next_publishers => publishers"
$CMD --publishers=$NEXT_PUBLISHERS payfee

$CMD --publishers=$NEXT_PUBLISHERS sign-seq --owner-btc-key-wif cMec2DGaTXkYJYfi7x3ZGjRXkeqmAvYAoWzMAcWj5fdLaqudWsNi --goat-block-number $GOAT_BLOCK_NUMBER --next-publishers=$PUBLISHERS --clean-sigs

# submit update-seq-set to GOAT
$CMD --publishers=$NEXT_PUBLISHERS --goat-evm-prvkey 0xbb094981331d23f14f6fec3749c2bc6effa582d52a0c92c6b257809d89d37ab6 update-seq-set --goat-block-number $GOAT_BLOCK_NUMBER --next-publishers=$PUBLISHERS 
$CMD --publishers=$NEXT_PUBLISHERS --goat-evm-prvkey 0x134e45328c0cf16fa450e9b40c34cba16a7eac2001b907f1de6a28549776f93e update-seq-set --goat-block-number $GOAT_BLOCK_NUMBER --next-publishers=$PUBLISHERS 

# sign offchain 
$CMD --publishers=$NEXT_PUBLISHERS --goat-evm-prvkey 0xbb094981331d23f14f6fec3749c2bc6effa582d52a0c92c6b257809d89d37ab6 sign-pub --next-publishers=$PUBLISHERS
$CMD --publishers=$NEXT_PUBLISHERS --goat-evm-prvkey 0x134e45328c0cf16fa450e9b40c34cba16a7eac2001b907f1de6a28549776f93e sign-pub --next-publishers=$PUBLISHERS

# update publisher on GOAT
$CMD --publishers=$NEXT_PUBLISHERS push-pub --goat-block-number $GOAT_BLOCK_NUMBER --next-publishers=$PUBLISHERS --next-publisher-btc-pubkeys=$PUBLISHERS_BTC_PUBKEYS

# broadcast publisher changes to Bitcoin
$CMD --publishers=$NEXT_PUBLISHERS push-seq --goat-block-number $GOAT_BLOCK_NUMBER --next-publishers=$PUBLISHERS
