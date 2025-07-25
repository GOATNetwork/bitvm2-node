# BitVM2 Covenant

See [Reth Processor](https://github.com/ziren/reth-processor/blob/main/README.md)

## Start by source code

### Parallel block execution

The block execution statistics are stored in a Sqlite database, and the number of blocks executed in parallel can be customized with the `MAX_CONCURRENT_EXECUTIONS` environment variable.

```shell
cargo run --bin continuous -- --block-number 1 --rpc-url https://archive.goat.network --chain-id 2345 --prove
```

### Aggregate block proofs

Aggregate block proofs and generate groth16 proofs.

```shell
cargo run --bin aggregation -- --block-number 1 --start
```

### Test getting groth16 proofs

```shell
RUST_LOG=debug cargo test test_groth16_proof
```

## Start by docker

### Start Proof Services

```
# DB directory in host.
export DB_DIR=

BLOCK_NUMBER=1 docker-compose up -d continuous

BLOCK_NUMBER=2 docker-compose up -d aggregation

# BLOCK_NUMBER=1 docker-compose up -d
```

### Stop Proof Services

```
docker-compose down continuous

docker-compose down aggregation

# docker-compose down
```

### View logs

```
tail -f logs/continuous.log.2025-07-23

tail -f logs/aggregation.log.2025-07-23

docker logs -f continuous

docker logs -f aggregation
```
