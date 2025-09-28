#!/bin/bash

i=${1-100}

if [ $i == 100 ]; then
  RUST_LOG=info cargo run -r -- --start 0 --batch-size 100 --init-input --output-proof "0-100.bin"
fi

echo $i
while true; do
  echo "Running for i=$i"
  RUST_LOG=info cargo run -r -- \
    --start "$i" \
    --batch-size 100 \
    --input-proof "$((i-100))-100.bin" \
    --output-proof "$i-100.bin" --force-fetch
  i=$((i+100))
done
