#!/bin/bash
bitvm2-noded -d --rpc-addr 0.0.0.0:9100 --db-path /var/data/bitvm2-node-0.db --p2p-port 8443  --bootnodes $BOOTNODES
