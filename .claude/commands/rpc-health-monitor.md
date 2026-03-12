Monitor goat-node RPC health by polling graph or instance status counts, node online state, and an overall service verdict.

## Instructions

1. Ask the user for the following parameters (skip any already provided as arguments: $ARGUMENTS):
   - **rpc_url**: Node API base URL. Default: `http://127.0.0.1:8011`
   - **once**: Run one snapshot and exit. Default: `true`
   - **interval**: Poll interval seconds when running continuously. Default: `30`
   - **timeout**: Per-request timeout seconds. Default: `8`
   - **page_size**: Pagination size for list endpoints. Default: `100`
   - **json_output**: Whether to print JSON output. Default: `false`
   - **show_all_checks**: Whether to print every endpoint check line. Default: `false`
   - **fail_on**: Exit policy in once mode. One of `none|degraded|unhealthy`. Default: `unhealthy`
   - **header_chain_height_url**: Header chain tip-height base URL. Default: `https://mempool.space/testnet4`
   - **state_chain_rpc_url**: State chain JSON-RPC URL. Default: `https://rpc.testnet3.goat.network`
   - **header_chain_lag_alert_blocks**: Header chain lag alert threshold (blocks). Default: `30`
   - **state_chain_lag_alert_blocks**: State chain lag alert threshold (blocks). Default: `200`

2. Check Python runtime and script path:
   ```bash
   python3 --version
   test -f ./.claude/commands/rpc-health-monitor.py && echo "script exists"
   ```

3. Run one-shot health snapshot (recommended):
   ```bash
   python3 ./.claude/commands/rpc-health-monitor.py \
     --base-url <rpc_url> \
       --header-chain-height-url <header_chain_height_url> \
       --state-chain-rpc-url <state_chain_rpc_url> \
       --header-chain-lag-alert-blocks <header_chain_lag_alert_blocks> \
       --state-chain-lag-alert-blocks <state_chain_lag_alert_blocks> \
     --once
   ```

4. Optional run modes:

   JSON output:
   ```bash
   python3 ./.claude/commands/rpc-health-monitor.py \
     --base-url <rpc_url> \
     --once --json
   ```

   Show all endpoint checks:
   ```bash
   python3 ./.claude/commands/rpc-health-monitor.py \
     --base-url <rpc_url> \
     --once --show-all-checks
   ```

   Continuous monitoring:
   ```bash
   python3 ./.claude/commands/rpc-health-monitor.py \
     --base-url <rpc_url> \
     --interval <interval>
   ```

5. Explain the output to the user:
   - `RPC liveness`: checks `/v1/nodes/overview` as the liveness probe
   - `Graph status counts`: counts by `graphs[].graph.status`
   - `Instance status counts`: split by bridge-in and bridge-out
   - `Node status counts`: online or offline counts from `/v1/nodes`
   - `Node overview`: actor-level online or offline summary from `/v1/nodes/overview`
   - `Operator/Committee liveness`: `operator_ok` and `committee_ok`
   - `Proof-builder latency stats`: chain proof `proving_time`, `total_time_to_proof`, `updated_delay_secs`, and `chain_lag`
   - `VERDICT`: `HEALTHY`, `DEGRADED`, or `UNHEALTHY`

6. If verdict is `DEGRADED` or `UNHEALTHY`, prioritize these checks:
   - endpoint failures in `Core endpoint checks`
   - `Hard issues` for blocking problems
   - `Soft issues` for degraded problems
   - rpc alert rule: if RPC is unavailable, raise direct alert immediately
   - liveness rules: any offline committee or no online operator is a problem
    - proof-builder alert rules (compare latest proof height vs latest chain height):
       - header-chain alert when lag is greater than `header_chain_lag_alert_blocks` (default `30`)
       - state-chain alert when lag is greater than `state_chain_lag_alert_blocks` (default `200`)
    - external chain rpc sources are configurable:
       - header chain rpc via `--header-chain-height-url` (default `https://mempool.space/testnet4`)
       - state chain rpc via `--state-chain-rpc-url` (default `https://rpc.testnet3.goat.network`)

## Examples

```bash
# testnet4 public RPC
python3 ./.claude/commands/rpc-health-monitor.py \
  --base-url https://bitvm2-api-testnet4.goat.network \
  --once

# override proof-builder lag thresholds and chain RPC sources
python3 ./.claude/commands/rpc-health-monitor.py \
   --base-url https://bitvm2-api-testnet4.goat.network \
   --header-chain-height-url https://mempool.space/testnet4 \
   --state-chain-rpc-url https://rpc.testnet3.goat.network \
   --header-chain-lag-alert-blocks 30 \
   --state-chain-lag-alert-blocks 200 \
   --once
