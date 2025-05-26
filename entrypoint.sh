#!/bin/bash

bn=""
if [ -n "$BOOTNODES" ]; then
    bn="--bootnodes $BOOTNODES"
fi

bitvm2-noded --rpc-addr 0.0.0.0:9100 --db-path /var/data/bitvm2-node-0.db --p2p-port 8443 $bn
