#!/bin/bash
set -e
export BITCOIN_NETWORK=regtest

_start=0
start=${1:-$_start}
_batch=2000
batch=${2:-$_batch}

function find_input_proof() {
  local start="$1"
  local input_file
  input_file=$(find . -maxdepth 1 -type f -name '*-*.bin' -printf '%f\n' |
    awk -v sum="$start" -F '[-.]' '($1 + $2) == sum { print $0; exit }')

  if [ ! $input_file ]; then
    echo "Can not find the input proof"
    exit -1
  fi
  echo $input_file
}

if [ $start -ne 0 ]; then
  input_file=$(find_input_proof $start)
else
  RUST_LOG=info cargo run -r -- --start 0 --batch-size $batch --init-input --output-proof "0-${batch}.bin" --force-fetch
  input_file="0-${batch}.bin"
  start=$batch
fi

echo "Start i=$start, batch=$batch"

while true; do
  echo "Running for i=$start"
  RUST_LOG=info cargo run -r -- \
    --start "$start" \
    --batch-size $batch \
    --input-proof $input_file \
    --output-proof "$start-${batch}.bin" --force-fetch
  input_file="$start-${batch}.bin"
  start=$((start + batch))
done
