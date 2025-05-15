# BitVM2 Covenant

See [Reth Processor](https://github.com/zkMIPS/reth-processor/blob/main/README.md)

## Parallel block execution

The block execution statistics are stored in a Sqlite database, and the number of blocks executed in parallel can be customized with the `MAX_CONCURRENT_EXECUTIONS` environment variable.

```angular2html
cargo run --bin continuous -- --block-number 1 --rpc-url https://archive.goat.network --chain-id 2345 --prove
```
