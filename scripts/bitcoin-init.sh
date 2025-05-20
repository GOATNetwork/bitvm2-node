#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

bitcoind -daemon \
   -server=1  \
   -datadir=/bitcoin \
   -regtest=1 \
   -txindex=1 \
   -fallbackfee='0.01' \
   -rpcallowip=0.0.0.0/0 \
   -rpcbind=0.0.0.0 \
   -rpcuser=111111 \
   -rpcpassword=111111

# Wait until RPC is ready
sleep 5
while ! bitcoin-cli -regtest -rpcuser=111111 -rpcpassword=111111 getblockchaininfo > /dev/null 2>&1; do
  echo "Waiting for bitcoind..."
  sleep 2
done

# install bitcoin-cli on MacOS: `brew install bitcoin`
export BTC="${USE_DOCKER} bitcoin-cli -regtest -rpcuser=111111 -rpcpassword=111111"

$BTC -named createwallet \
    wallet_name=alice \
    passphrase="btcstaker" \
    load_on_startup=true \
    descriptors=false

$BTC loadwallet "alice"

$BTC --rpcwallet=alice walletpassphrase "btcstaker" 600

$BTC --rpcwallet=alice -generate 1000

address="bcrt1q7tr8sl50zanztcrps35hakqpe7gmfzedhhnxcspj7n0ks5lyrnhs6m8ewg"
## fund the address
$BTC --rpcwallet=alice sendtoaddress $address 1
$BTC --rpcwallet=alice -generate 10

# Install watch
apt-get update
apt-get install -y procps
# A terminal-based program (like watch, top, less, etc.) runs in an environment, TERM environment variable should be set
export TERM=xterm
watch -n 2 "$BTC -generate 1"