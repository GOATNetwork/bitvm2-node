#!/bin/bash
set -e
#CMD="cargo run -r --bin header-chain-proof --package header-chain-proof --"
CMD="../target/release/header-chain-proof"
DATA="data/header-chain"

_start=0
start=${1:-$_start}
_batch=2000
batch=${2:-$_batch}

function find_input_proof() {
  local start="$1"
  local input_file
  input_file=$(find $DATA -maxdepth 1 -type f -regex '.*[0-9]+-[0-9]+\.bin$' -printf '%f\n' |
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
