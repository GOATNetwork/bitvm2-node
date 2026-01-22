nohup ../bitvm2-noded  --rpc-addr 127.0.0.1:8902   --db-path sqlite:$PWD/bitvm2-node.db --p2p-port 8445   >$PWD/$(date +'%Y%m%d').log 2>&1 &
