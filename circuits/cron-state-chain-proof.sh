#!/bin/bash
set -e
CMD="cargo run -r --bin state-chain-proof --package state-chain-proof"
DATA="data/state-chain"
_start=$EL_START_BLOCK_NUMBER
start=${1:-$_start}
_batch=2000
batch=${2:-$_batch}

function find_input_proof() {
  local start="$1"
  local input_file
  input_file=$(find $DATA -maxdepth 1 -type f -name '*-*.bin' -printf '%f\n' |
    awk -v sum="$start" -F '[-.]' '($1 + $2) == sum { print $0; exit }')

  if [ ! $input_file ]; then
    echo "Can not find the input proof"
    exit -1
  fi
  echo $input_file
}

if [ $start -ne $EL_START_BLOCK_NUMBER ]; then
  input_file=$(find_input_proof $start)
else
  RUST_LOG=info $CMD -- --start $EL_START_BLOCK_NUMBER --batch-size $batch --init-input --output-proof "${DATA}/${start}-${batch}.bin" --blocks $DATA/${start}-${batch}.blocks
  input_file="$start-${batch}.bin"
  start=$(($start + $batch))
fi

echo "Start i=$start, batch=$batch"

while true; do
  echo "Running for i=$start"
  RUST_LOG=info $CMD -- \
    --start "$start" \
    --batch-size $batch \
    --blocks $DATA/${start}-${batch}.blocks \
    --input-proof $DATA/$input_file \
    --output-proof "${DATA}/$start-${batch}.bin"
  input_file="$start-${batch}.bin"
  start=$((start + batch))
done
