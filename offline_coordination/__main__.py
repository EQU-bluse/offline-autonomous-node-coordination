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


def _read_run_materials(args: argparse.Namespace) -> tuple[object, bytes] | None:
    """Read the keyring and ticket material files for ``recovery run``."""
    try:
        with open(args.keyring, "rb") as handle:
            keyring = json.loads(handle.read().decode("utf-8"))
        with open(args.ticket, "rb") as handle:
            ticket = handle.read()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"cannot read recovery materials: {exc}", file=sys.stderr)
        return None
    return keyring, ticket


def main() -> int:
    parser = argparse.ArgumentParser(prog="offline-coordination")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status")
    recovery = subparsers.add_parser("recovery")
    recovery.add_argument("action", choices=["check", "run", "audit"])
    recovery.add_argument("paths", nargs="+")
    recovery.add_argument("--keyring")
    recovery.add_argument("--ticket")
    recovery.add_argument("--moment", type=int)
    recovery.add_argument("--audit")
    recovery.add_argument("--after", type=int, default=0)
    recovery.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()
    if args.command == "status":
        print(json.dumps(status(), sort_keys=True))
        return 0
    try:
        if args.action == "check":
            items = replication.inspect_recovery(args.paths)
        elif args.action == "run":
            if any(
                getattr(args, name) is None
                for name in ("keyring", "ticket", "moment", "audit")
            ):
                print(
                    "recovery run requires --keyring, --ticket, --moment "
                    "and --audit",
                    file=sys.stderr,
                )
                return 2
            materials = _read_run_materials(args)
            if materials is None:
                return 2
            keyring, ticket = materials
            items = replication.recover_authorized(
                args.paths, keyring, ticket, args.moment, args.audit
            )
        else:
            if len(args.paths) != 1:
                print(
                    "recovery audit takes exactly one audit path",
                    file=sys.stderr,
                )
                return 2
            _emit_line(
                replication.export_recovery_audit(
                    args.paths[0], after=args.after, limit=args.limit
                )
            )
            return 0
    except (TypeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    _emit_line(items)
    return 1 if any(item["error"] is not None for item in items) else 0


if __name__ == "__main__":
    raise SystemExit(main())
