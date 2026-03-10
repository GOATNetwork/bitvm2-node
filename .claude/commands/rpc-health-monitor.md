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

2. Check Python runtime and script path:
   ```bash
   python3 --version
   test -f ./.claude/commands/rpc-health-monitor.py && echo "script exists"
   ```

3. Run one-shot health snapshot (recommended):
   ```bash
   python3 ./.claude/commands/rpc-health-monitor.py \
     --base-url <rpc_url> \
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
   - `Graph status counts`: counts by `graphs[].graph.status`
   - `Instance status counts`: split by bridge-in and bridge-out
   - `Node status counts`: online or offline counts from `/v1/nodes`
   - `Node overview`: actor-level online or offline summary from `/v1/nodes/overview`
   - `VERDICT`: `HEALTHY`, `DEGRADED`, or `UNHEALTHY`

6. If verdict is `DEGRADED` or `UNHEALTHY`, prioritize these checks:
   - endpoint failures in `Core endpoint checks`
   - `Issues` section for list or overview fetch failures
   - whether all nodes are offline

## Examples

```bash
# testnet4 public RPC
python3 ./.claude/commands/rpc-health-monitor.py \
  --base-url https://bitvm2-api-testnet4.goat.network \
  --once
