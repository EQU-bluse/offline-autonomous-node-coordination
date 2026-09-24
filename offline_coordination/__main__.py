from __future__ import annotations

import argparse
import json
import sys

from offline_coordination import replication


def status() -> dict[str, object]:
    return {
        "nodeId": "local-node",
        "connectivity": "offline",
        "revision": 0,
        "pendingChanges": 0,
    }


def _emit_line(payload: object) -> None:
    """Print one compact UTF-8 JSON line with recursively sorted keys."""
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def main() -> int:
    parser = argparse.ArgumentParser(prog="offline-coordination")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status")
    recovery = subparsers.add_parser("recovery")
    recovery.add_argument("action", choices=["check", "run"])
    recovery.add_argument("paths", nargs="+")
    args = parser.parse_args()
    if args.command == "status":
        print(json.dumps(status(), sort_keys=True))
        return 0
    try:
        if args.action == "check":
            items = replication.inspect_recovery(args.paths)
        else:
            items = replication.recover_many(args.paths)
    except (TypeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    _emit_line(items)
    return 1 if any(item["error"] is not None for item in items) else 0


if __name__ == "__main__":
    raise SystemExit(main())
