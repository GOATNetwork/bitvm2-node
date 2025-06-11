# BitVM2 Covenant

See [Reth Processor](https://github.com/zkMIPS/reth-processor/blob/main/README.md)

## Parallel block execution

The block execution statistics are stored in a Sqlite database, and the number of blocks executed in parallel can be customized with the `MAX_CONCURRENT_EXECUTIONS` environment variable.

```shell
cargo run --bin continuous -- --block-number 1 --rpc-url https://archive.goat.network --chain-id 2345 --prove
```

## Aggregate block proofs

Aggregate block proofs and generate groth16 proofs.

```shell
cargo run --bin aggregation -- --block-number 2
```
