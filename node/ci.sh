set -e
source .env

rm -rf /tmp/output.data

cargo run --bin sequencer-set-publish -- fund 

# payfee
cargo run --bin sequencer-set-publish -- payfee

# sign sequencer set publishing genisis txn 
cargo run --bin sequencer-set-publish -- push-seq --goat-block-number 10000

cargo run --bin sequencer-set-publish -- payfee

cargo run --bin sequencer-set-publish -- sign-seq --owner-btc-key-wif cMec2DGaTXkYJYfi7x3ZGjRXkeqmAvYAoWzMAcWj5fdLaqudWsNi \
    --goat-block-number 10000 
cargo run --bin sequencer-set-publish -- sign-seq --owner-btc-key-wif cMgZD2qsGReP1UvGbNQ7moL6PZFgzsuPFV3St8sGwpNxED4hqkEM \
    --goat-block-number 10000
cargo run --bin sequencer-set-publish -- sign-seq --owner-btc-key-wif cMiWPrRA5KYDiRAq4nkgGsEf2TfcpqGbhT6YbfDpoy8ZsaAHiDeo \
    --goat-block-number 10000

# submit update-seq-set to GOAT
cargo run -r --bin sequencer-set-publish -- --goat-evm-prvkey 0xbb094981331d23f14f6fec3749c2bc6effa582d52a0c92c6b257809d89d37ab6 update-seq-set --goat-block-number 10000
cargo run -r --bin sequencer-set-publish -- --goat-evm-prvkey 0x134e45328c0cf16fa450e9b40c34cba16a7eac2001b907f1de6a28549776f93e update-seq-set --goat-block-number 10000
cargo run -r --bin sequencer-set-publish -- --goat-evm-prvkey 0xe079ee9ddc9440df0e55ca9966b87cdf145dad8cd04a7d6795f80a37a6130305 update-seq-set --goat-block-number 10000
cargo run -r --bin sequencer-set-publish -- --goat-evm-prvkey 0xc12bb8b3c48eb1ffd8f573dd9a7da45b06b739a647f5ee60a8a91430a102fbf7 update-seq-set --goat-block-number 10000

cargo run --bin sequencer-set-publish -- push-seq --goat-block-number 10000 

# update publisher
cargo run -r --bin sequencer-set-publish -- --goat-evm-prvkey 0xbb094981331d23f14f6fec3749c2bc6effa582d52a0c92c6b257809d89d37ab6 sign-pub --goat-block-number 10000
cargo run -r --bin sequencer-set-publish -- --goat-evm-prvkey 0x134e45328c0cf16fa450e9b40c34cba16a7eac2001b907f1de6a28549776f93e sign-pub --goat-block-number 10000
cargo run -r --bin sequencer-set-publish -- --goat-evm-prvkey 0xe079ee9ddc9440df0e55ca9966b87cdf145dad8cd04a7d6795f80a37a6130305 sign-pub --goat-block-number 10000
cargo run -r --bin sequencer-set-publish -- --goat-evm-prvkey 0xc12bb8b3c48eb1ffd8f573dd9a7da45b06b739a647f5ee60a8a91430a102fbf7 sign-pub --goat-block-number 10000

cargo run --bin sequencer-set-publish -- push-pub --goat-block-number 10000 

