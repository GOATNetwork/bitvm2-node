#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RPC_USER=111111
RPC_PSWD=111111
WALLET_NAME=alice
WALLET_PASSPHRASE=btcstaker

bitcoind -daemon \
   -server=1  \
   -datadir=/bitcoin \
   -regtest=1 \
   -txindex=1 \
   -fallbackfee='0.01' \
   -rpcallowip=0.0.0.0/0 \
   -rpcbind=0.0.0.0 \
   -rpcuser=$RPC_USER \
   -rpcpassword=$RPC_PSWD

# Wait until RPC is ready
sleep 5
while ! bitcoin-cli -regtest -rpcuser=$RPC_USER -rpcpassword=$RPC_PSWD getblockchaininfo > /dev/null 2>&1; do
  echo "Waiting for bitcoind..."
  sleep 2
done

# install bitcoin-cli on MacOS: `brew install bitcoin`
export BTC="${USE_DOCKER} bitcoin-cli -regtest -rpcuser=$RPC_USER -rpcpassword=$RPC_PSWD"

$BTC -named createwallet \
    wallet_name=$WALLET_NAME \
    passphrase=$WALLET_PASSPHRASE \
    load_on_startup=true \
    descriptors=false

$BTC loadwallet $WALLET_NAME

$BTC --rpcwallet=$WALLET_NAME walletpassphrase $WALLET_PASSPHRASE 600

address="bcrt1q7tr8sl50zanztcrps35hakqpe7gmfzedhhnxcspj7n0ks5lyrnhs6m8ewg"
## fund the address
$BTC --rpcwallet=$WALLET_NAME -generate 101
$BTC --rpcwallet=$WALLET_NAME sendtoaddress $address 20

# Install watch
apt-get update
apt-get install -y procps
# A terminal-based program (like watch, top, less, etc.) runs in an environment, TERM environment variable should be set
export TERM=xterm
watch -n 2 "$BTC -generate 1 && $BTC walletpassphrase $WALLET_PASSPHRASE 600 && $BTC keypoolrefill"
