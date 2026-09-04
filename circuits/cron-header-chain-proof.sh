#!/bin/bash
set -e
source .env
BITCOIN_NETWORK=$BITCOIN_NETWORK cargo build -r --bin header-chain-proof --package header-chain-proof
CMD="../target/release/header-chain-proof"
DATA="data/header-chain"

_start=0
start=${1:-$_start}
_batch=2000
batch=${2:-$_batch}

function find_input_proof() {
  local start="$1"
  local input_file=""
  local proof_path
  local proof_file
  local proof_start
  local proof_batch

  # Match proof files by filename because batch size may vary between runs.
  shopt -s nullglob
  for proof_path in "$DATA"/*.bin; do
    proof_file="${proof_path##*/}"
    if [[ "$proof_file" =~ ^([0-9]+)-([0-9]+)\.bin$ ]]; then
      proof_start="${BASH_REMATCH[1]}"
      proof_batch="${BASH_REMATCH[2]}"
      if (( proof_start + proof_batch == start )); then
        input_file="$proof_file"
        break
      fi
    fi
  done
  shopt -u nullglob

  if [ -z "$input_file" ]; then
    echo "Can not find the input proof for start=$start in $DATA" >&2
    exit 1
  fi
  echo "$input_file"
}

if [ $start -ne 0 ]; then
  input_file=$(find_input_proof $start)
else
  RUST_LOG=info $CMD --start 0 --batch-size $batch --init-input --output-proof "${DATA}/0-${batch}.bin" --block-headers $DATA/block_headers.bin --force-fetch
  input_file="0-${batch}.bin"
  start=$batch
fi

echo "Start i=$start, batch=$batch"

while true; do
  echo "Running for i=$start"
  #cp $DATA/${start}-${batch}.bin.blocks $DATA/block_headers.bin
  RUST_LOG=info $CMD \
    --start "$start" \
    --batch-size $batch \
    --block-headers $DATA/block_headers.bin \
    --input-proof $DATA/$input_file \
    --output-proof "${DATA}/$start-${batch}.bin" --force-fetch
  input_file="$start-${batch}.bin"
  start=$((start + batch))
done
