#!/bin/bash
set -e
export BITCOIN_NETWORK=regtest

batch=2000
i=${1:-$batch}
if [ $i -eq $batch ]; then
  RUST_LOG=info cargo run -r -- --start 0 --batch-size $batch --init-input --output-proof "0-${batch}.bin"
fi

echo "Start i=$i, batch=$batch"

while true; do
  echo "Running for i=$i"
  RUST_LOG=info cargo run -r -- \
    --start "$i" \
    --batch-size $batch \
    --input-proof "$((i - batch))-${batch}.bin" \
    --output-proof "$i-${batch}.bin" --force-fetch
  i=$((i + batch))
done
