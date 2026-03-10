#!/usr/bin/env python3
"""RPC health monitor for goat-node.

Collects and summarizes:
1) graph status counts
2) instance status counts (bridge-in/out)
3) node online or offline status
4) overall service health verdict
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class EndpointCheck:
    name: str
    path: str
    ok: bool
    latency_ms: int
    detail: str


SEVERITY = {"HEALTHY": 0, "DEGRADED": 1, "UNHEALTHY": 2}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_url(base_url: str, path: str, params: Optional[Dict[str, Any]] = None) -> str:
    base = base_url.rstrip("/")
    rel = path if path.startswith("/") else "/" + path
    # If caller already uses a /v1 base URL, avoid producing /v1/v1/... paths.
    if rel.startswith("/v1") and base.endswith("/v1"):
        rel = rel[3:] or "/"
    url = f"{base}{rel}"
    if params:
        clean = {k: v for k, v in params.items() if v is not None}
        if clean:
            url = f"{url}?{urllib.parse.urlencode(clean)}"
    return url


def http_get(base_url: str, path: str, timeout: int, params: Optional[Dict[str, Any]] = None) -> Tuple[int, str, int]:
    url = build_url(base_url, path, params)
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    start = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body, int((time.monotonic() - start) * 1000)
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", errors="replace")
        return err.code, body, int((time.monotonic() - start) * 1000)


def get_json(
    base_url: str,
    path: str,
    timeout: int,
    params: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], EndpointCheck]:
    status, body, latency = http_get(base_url, path, timeout, params=params)
    if status < 200 or status >= 300:
        raise RuntimeError(f"HTTP {status}: {body[:300]}")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as err:
        raise RuntimeError(f"invalid json: {err}") from err
    check = EndpointCheck(name=path, path=build_url(base_url, path, params), ok=True, latency_ms=latency, detail="ok")
    return payload, check


def get_text_check(base_url: str, path: str, timeout: int) -> EndpointCheck:
    status, body, latency = http_get(base_url, path, timeout)
    if status < 200 or status >= 300:
        return EndpointCheck(
            name=path,
            path=build_url(base_url, path),
            ok=False,
            latency_ms=latency,
            detail=f"HTTP {status}: {body[:160]}",
        )
    return EndpointCheck(name=path, path=build_url(base_url, path), ok=True, latency_ms=latency, detail="ok")


def fetch_pages(
    base_url: str,
    path: str,
    item_key: str,
    timeout: int,
    page_size: int,
    fixed_params: Optional[Dict[str, Any]] = None,
    max_pages: int = 1000,
) -> Tuple[List[Dict[str, Any]], int, List[EndpointCheck]]:
    all_items: List[Dict[str, Any]] = []
    checks: List[EndpointCheck] = []
    total = 0
    offset = 0
    params = dict(fixed_params or {})

    for _ in range(max_pages):
        page_params = dict(params)
        page_params["offset"] = offset
        page_params["limit"] = page_size
        payload, check = get_json(base_url, path, timeout, page_params)
        checks.append(check)

        if not isinstance(payload, dict):
            raise RuntimeError(f"{path}: payload is not object")

        page_items = payload.get(item_key, [])
        if not isinstance(page_items, list):
            raise RuntimeError(f"{path}: {item_key} is not list")

        if total == 0:
            try:
                total = int(payload.get("total", 0))
            except (TypeError, ValueError) as err:
                raise RuntimeError(f"{path}: invalid total field") from err

        all_items.extend(page_items)
        if len(page_items) < page_size:
            break
        offset += page_size
    else:
        raise RuntimeError(f"{path}: pagination exceeded max_pages={max_pages}")

    return all_items, total, checks


def count_by(items: List[Dict[str, Any]], extractor: Callable[[Dict[str, Any]], str]) -> Dict[str, int]:
    counter: Counter[str] = Counter()
    for item in items:
        status = extractor(item)
        counter[status or "UNKNOWN"] += 1
    return dict(sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])))


def summarize_once(base_url: str, timeout: int, page_size: int) -> Dict[str, Any]:
    # Public RPCs often cap limit at 100.
    page_size = max(1, min(page_size, 100))

    checks: List[EndpointCheck] = []
    optional_checks: List[EndpointCheck] = []
    issues: List[str] = []

    root_check = get_text_check(base_url, "/", timeout)
    optional_checks.append(root_check)

    metrics_check = get_text_check(base_url, "/metrics", timeout)
    optional_checks.append(metrics_check)

    try:
        instances_overview, overview_check = get_json(base_url, "/v1/instances/overview", timeout)
        checks.append(overview_check)
    except Exception as err:  # pylint: disable=broad-except
        instances_overview = {}
        issues.append(f"instances_overview failed: {err}")

    try:
        nodes_overview_resp, nodes_overview_check = get_json(base_url, "/v1/nodes/overview", timeout)
        checks.append(nodes_overview_check)
        nodes_overview = nodes_overview_resp.get("nodes_overview", {})
        if not isinstance(nodes_overview, dict):
            nodes_overview = {}
            issues.append("nodes_overview payload invalid")
    except Exception as err:  # pylint: disable=broad-except
        nodes_overview = {}
        issues.append(f"nodes_overview failed: {err}")

    graph_items: List[Dict[str, Any]] = []
    graph_total = 0
    try:
        graph_items, graph_total, graph_checks = fetch_pages(
            base_url,
            "/v1/graphs",
            "graphs",
            timeout,
            page_size,
            fixed_params={},
        )
        checks.extend(graph_checks)
    except Exception as err:  # pylint: disable=broad-except
        issues.append(f"graph list failed: {err}")

    instance_in_items: List[Dict[str, Any]] = []
    instance_in_total = 0
    try:
        instance_in_items, instance_in_total, in_checks = fetch_pages(
            base_url,
            "/v1/instances",
            "instance_wraps",
            timeout,
            page_size,
            fixed_params={"is_bridge_in": "true"},
        )
        checks.extend(in_checks)
    except Exception as err:  # pylint: disable=broad-except
        issues.append(f"bridge-in instance list failed: {err}")

    instance_out_items: List[Dict[str, Any]] = []
    instance_out_total = 0
    try:
        instance_out_items, instance_out_total, out_checks = fetch_pages(
            base_url,
            "/v1/instances",
            "instance_wraps",
            timeout,
            page_size,
            fixed_params={"is_bridge_in": "false"},
        )
        checks.extend(out_checks)
    except Exception as err:  # pylint: disable=broad-except
        issues.append(f"bridge-out instance list failed: {err}")

    node_items: List[Dict[str, Any]] = []
    node_total = 0
    try:
        node_items, node_total, node_checks = fetch_pages(
            base_url,
            "/v1/nodes",
            "nodes",
            timeout,
            page_size,
            fixed_params={},
        )
        checks.extend(node_checks)
    except Exception as err:  # pylint: disable=broad-except
        issues.append(f"node list failed: {err}")

    graph_status_counts = count_by(
        graph_items,
        lambda x: (
            (x.get("graph") or {}).get("status")
            if isinstance(x, dict) and isinstance(x.get("graph"), dict)
            else "MISSING_GRAPH"
        ),
    )

    instance_in_status_counts = count_by(
        instance_in_items,
        lambda x: (
            (x.get("instance") or {}).get("status")
            if isinstance(x, dict) and isinstance(x.get("instance"), dict)
            else "MISSING_INSTANCE"
        ),
    )
    instance_out_status_counts = count_by(
        instance_out_items,
        lambda x: (
            (x.get("instance") or {}).get("status")
            if isinstance(x, dict) and isinstance(x.get("instance"), dict)
            else "MISSING_INSTANCE"
        ),
    )
    node_status_counts = count_by(
        node_items,
        lambda x: x.get("status") if isinstance(x, dict) else "UNKNOWN",
    )

    if graph_total and graph_total != len(graph_items):
        issues.append(f"graph total mismatch: expected {graph_total}, got {len(graph_items)}")
    if instance_in_total and instance_in_total != len(instance_in_items):
        issues.append(
            f"bridge-in total mismatch: expected {instance_in_total}, got {len(instance_in_items)}"
        )
    if instance_out_total and instance_out_total != len(instance_out_items):
        issues.append(
            f"bridge-out total mismatch: expected {instance_out_total}, got {len(instance_out_items)}"
        )
    if node_total and node_total != len(node_items):
        issues.append(f"node total mismatch: expected {node_total}, got {len(node_items)}")

    online_nodes = int(node_status_counts.get("Online", 0) + node_status_counts.get("online", 0))
    if node_total > 0 and online_nodes == 0:
        issues.append("all nodes are offline")

    critical_fail = any("failed:" in issue for issue in issues)

    verdict = "HEALTHY"
    if critical_fail:
        verdict = "UNHEALTHY"
    elif issues:
        verdict = "DEGRADED"

    return {
        "generated_at": utc_now(),
        "base_url": base_url,
        "verdict": verdict,
        "issues": issues,
        "graph": {
            "total": len(graph_items),
            "status_counts": graph_status_counts,
        },
        "instance": {
            "bridge_in_total": len(instance_in_items),
            "bridge_in_status_counts": instance_in_status_counts,
            "bridge_out_total": len(instance_out_items),
            "bridge_out_status_counts": instance_out_status_counts,
        },
        "node": {
            "total": len(node_items),
            "status_counts": node_status_counts,
            "nodes_overview": nodes_overview,
        },
        "instances_overview": instances_overview,
        "endpoint_checks": [c.__dict__ for c in checks],
        "optional_checks": [c.__dict__ for c in optional_checks],
    }


def print_checks(title: str, checks: List[Dict[str, Any]], show_all: bool) -> None:
    if not checks:
        print(f"\n{title}: none")
        return

    failed = [c for c in checks if not c.get("ok", False)]
    passed = len(checks) - len(failed)
    print(f"\n{title}: {passed}/{len(checks)} passed")

    if show_all:
        for c in checks:
            mark = "OK" if c.get("ok", False) else "FAIL"
            print(f"  [{mark}] {c['path']} ({c['latency_ms']} ms) {c['detail']}")
        return

    if failed:
        print("  failed endpoints:")
        for c in failed:
            print(f"  [FAIL] {c['path']} ({c['latency_ms']} ms) {c['detail']}")


def print_human(snapshot: Dict[str, Any], show_all_checks: bool = False) -> None:
    print(f"[{snapshot['generated_at']}] RPC health snapshot for {snapshot['base_url']}")
    print(f"VERDICT: {snapshot['verdict']}")

    print("\nGraph status counts:")
    print(f"total={snapshot['graph']['total']}")
    for key, value in snapshot["graph"]["status_counts"].items():
        print(f"  {key}: {value}")

    print("\nInstance status counts (bridge-in):")
    print(f"total={snapshot['instance']['bridge_in_total']}")
    for key, value in snapshot["instance"]["bridge_in_status_counts"].items():
        print(f"  {key}: {value}")

    print("\nInstance status counts (bridge-out):")
    print(f"total={snapshot['instance']['bridge_out_total']}")
    for key, value in snapshot["instance"]["bridge_out_status_counts"].items():
        print(f"  {key}: {value}")

    print("\nNode status counts:")
    print(f"total={snapshot['node']['total']}")
    for key, value in snapshot["node"]["status_counts"].items():
        print(f"  {key}: {value}")

    nodes_overview = snapshot["node"].get("nodes_overview", {})
    if nodes_overview:
        print("\nNode overview:")
        for key, value in nodes_overview.items():
            print(f"  {key}: {value}")

    print_checks("Core endpoint checks", snapshot["endpoint_checks"], show_all_checks)
    print_checks("Optional endpoint checks", snapshot.get("optional_checks", []), show_all_checks)

    issues = snapshot.get("issues", [])
    if issues:
        print("\nIssues:")
        for issue in issues:
            print(f"  - {issue}")


def should_fail(verdict: str, fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = "UNHEALTHY" if fail_on == "unhealthy" else "DEGRADED"
    return SEVERITY[verdict] >= SEVERITY[threshold]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Monitor goat-node RPC health and status distributions")
    parser.add_argument("--base-url", default="http://127.0.0.1:8011", help="RPC base url")
    parser.add_argument("--interval", type=int, default=30, help="poll interval seconds")
    parser.add_argument("--timeout", type=int, default=8, help="single request timeout seconds")
    parser.add_argument("--page-size", type=int, default=100, help="pagination page size (1-100)")
    parser.add_argument("--once", action="store_true", help="run one snapshot and exit")
    parser.add_argument("--json", action="store_true", help="output JSON")
    parser.add_argument(
        "--show-all-checks",
        action="store_true",
        help="show every endpoint check line in human output",
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "degraded", "unhealthy"],
        default="unhealthy",
        help="when to return non-zero exit code in --once mode",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    def run_snapshot() -> int:
        try:
            snapshot = summarize_once(args.base_url, args.timeout, args.page_size)
        except Exception as err:  # pylint: disable=broad-except
            print(f"fatal monitor error: {err}", file=sys.stderr)
            return 2

        if args.json:
            print(json.dumps(snapshot, ensure_ascii=True, separators=(",", ":")))
        else:
            print_human(snapshot, args.show_all_checks)

        if args.once and should_fail(snapshot["verdict"], args.fail_on):
            return 1
        return 0

    if args.once:
        return run_snapshot()

    while True:
        code = run_snapshot()
        if code != 0:
            print(f"monitor warning: snapshot exit code={code}", file=sys.stderr)
        print("")
        time.sleep(max(1, args.interval))


if __name__ == "__main__":
    sys.exit(main())
