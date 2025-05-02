#!/bin/bash

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

#docker rm -f bitcoin-server
#docker run --name bitcoin-server -d -v $HOME/bitcoin:/root/bitcoin -p 18443:18443 -p 8332:8332 -p 18332:18332 -it ruimarinho/bitcoin-core -regtest=1 -rpcbind='0.0.0.0' -rpcallowip='0.0.0.0/0'  -fallbackfee='0.01' -txindex=1 -rpcuser=111111 -rpcpassword=111111
#sleep 2
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
#USE_DOCKER="docker exec -it bitcoin-server"
export BTC="${USE_DOCKER} bitcoin-cli -regtest -rpcuser=111111 -rpcpassword=111111"

$BTC -named createwallet \
    wallet_name=alice \
    passphrase="btcstaker" \
    load_on_startup=true \
    descriptors=false

$BTC loadwallet "alice"

$BTC --rpcwallet=alice walletpassphrase "btcstaker" 600

$BTC --rpcwallet=alice -generate 1000

## prepare a funded wallet
#address=`$BTC -rpcwallet=alice getnewaddress`
#$BTC importprivkey "cSWNzrM1CjFt1VZNBV7qTTr1t2fmZUgaQe2FL4jyFQRgTtrYp8Y5" "testonly" false
#address="bcrt1qvnhz5qn4q9vt2sgumajnm8gt53ggvmyyfwd0jg"

address="bcrt1q7tr8sl50zanztcrps35hakqpe7gmfzedhhnxcspj7n0ks5lyrnhs6m8ewg"
## fund the address
$BTC --rpcwallet=alice sendtoaddress $address 1
$BTC --rpcwallet=alice -generate 10

#privkey=`$BTC --rpcwallet=alice dumpprivkey  $address`
#echo $privkey > $DIR/../.key.test
tail -f /dev/null
