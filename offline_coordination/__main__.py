from __future__ import annotations

import argparse
import json


def status() -> dict[str, object]:
    return {
        "nodeId": "local-node",
        "connectivity": "offline",
        "revision": 0,
        "pendingChanges": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="offline-coordination")
    parser.add_argument("command", choices=["status"])
    args = parser.parse_args()
    if args.command == "status":
        print(json.dumps(status(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
