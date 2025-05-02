#!/bin/bash

docker rm -f bitcoin-server

docker run --name bitcoin-server -d -v $HOME/bitcoin:/root/bitcoin -p 18443:18443 -p 8332:8332 -p 18332:18332 -it ruimarinho/bitcoin-core -regtest=1 -rpcbind='0.0.0.0' -rpcallowip='0.0.0.0/0'  -fallbackfee='0.01' -txindex=1 -rpcuser=111111 -rpcpassword=111111

sleep 2
# install bitcoin-cli on MacOS: `brew install bitcoin`
export BTC="bitcoin-cli -regtest -rpcuser=111111 -rpcpassword=111111"

$BTC -named createwallet \
    wallet_name=alice \
    passphrase="btcstaker" \
    load_on_startup=true \
    descriptors=false

$BTC loadwallet "alice"
$BTC --rpcwallet=bob walletpassphrase "btcstaker" 600

$BTC --rpcwallet=alice -generate 100
