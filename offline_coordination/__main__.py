from __future__ import annotations

import argparse
import json
import sys

from offline_coordination import recovery_audit, replication
from offline_coordination.replication import (
    AuthenticationError,
    CorruptRecoveryAuditError,
    ReplayError,
)


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


def _load_json_material(parser: argparse.ArgumentParser, flag: str, path: str) -> object:
    """Load one JSON material file; every failure is a syntax/input error."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        parser.error(f"{flag} {path!r} cannot be read: {exc}")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        parser.error(f"{flag} {path!r} is not valid UTF-8 JSON: {exc}")


def _load_ticket_bytes(parser: argparse.ArgumentParser, path: str) -> bytes:
    """Load the raw ticket bytes; a read failure is a syntax/input error."""
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError as exc:
        parser.error(f"--ticket {path!r} cannot be read: {exc}")


def _run_authorized(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        moment = int(args.moment)
    except ValueError:
        parser.error("--moment must be an integer")
    keyring = _load_json_material(parser, "--keyring", args.keyring)
    ticket = _load_ticket_bytes(parser, args.ticket)
    try:
        items = replication.recover_authorized(
            args.paths, keyring, ticket, args.audit, moment
        )
    except (CorruptRecoveryAuditError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (AuthenticationError, ReplayError, TypeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    _emit_line(items)
    return 1 if any(item["error"] is not None for item in items) else 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="offline-coordination")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status")

    recovery = subparsers.add_parser("recovery")
    recovery_sub = recovery.add_subparsers(dest="action", required=True)

    check = recovery_sub.add_parser("check")
    check.add_argument("paths", nargs="+")

    run = recovery_sub.add_parser("run")
    run.add_argument("paths", nargs="+")
    run.add_argument("--keyring")
    run.add_argument("--ticket")
    run.add_argument("--audit")
    run.add_argument("--moment")

    audit_cmd = recovery_sub.add_parser("audit")
    audit_cmd.add_argument("audit_path")
    audit_cmd.add_argument("--after", default="0")
    audit_cmd.add_argument("--limit", default="100")

    args = parser.parse_args()
    if args.command == "status":
        print(json.dumps(status(), sort_keys=True))
        return 0

    if args.action == "audit":
        try:
            after = int(args.after)
            limit = int(args.limit)
            page = recovery_audit.export_page(args.audit_path, after, limit)
        except (CorruptRecoveryAuditError, OSError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        except (TypeError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        sys.stdout.buffer.write(page)
        return 0

    if args.action == "check":
        try:
            items = replication.inspect_recovery(args.paths)
        except (TypeError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        _emit_line(items)
        return 1 if any(item["error"] is not None for item in items) else 0

    signed_flags = (args.keyring, args.ticket, args.audit, args.moment)
    if any(value is not None for value in signed_flags):
        if any(value is None for value in signed_flags):
            run.error(
                "--keyring, --ticket, --audit and --moment must be given "
                "together"
            )
        return _run_authorized(args, run)

    try:
        items = replication.recover_many(args.paths)
    except (TypeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    _emit_line(items)
    return 1 if any(item["error"] is not None for item in items) else 0


if __name__ == "__main__":
    raise SystemExit(main())
