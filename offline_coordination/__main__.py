from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
import sys

from offline_coordination import replication


# Receiver-side byte budget used when the CLI passes no --max-bytes:
# taken straight from import_signed_batch's own default so the two can
# never drift apart.
_IMPORT_DEFAULT_MAX_BYTES = inspect.signature(
    replication.import_signed_batch
).parameters["max_bytes"].default


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


def _fail(message: object) -> int:
    """Write a deterministic error line to stderr and report exit code 2."""
    print(str(message), file=sys.stderr)
    return 2


def _read_json_utf8(path: str) -> object:
    """Read a UTF-8 JSON file, surfacing read, encoding and parse faults."""
    with open(path, "rb") as handle:
        return json.loads(handle.read().decode("utf-8"))


def _read_run_materials(args: argparse.Namespace) -> tuple[object, bytes] | None:
    """Read the keyring and ticket material files for ``recovery run``."""
    try:
        keyring = _read_json_utf8(args.keyring)
        with open(args.ticket, "rb") as handle:
            ticket = handle.read()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"cannot read recovery materials: {exc}", file=sys.stderr)
        return None
    return keyring, ticket


def _write_new_durable(path: str, data: bytes) -> None:
    """Create ``path`` with ``data`` durably, never overwriting.

    The file is created exclusively (``O_EXCL``), flushed and fsynced,
    followed by a directory fsync.  Any failure removes the partial
    destination so no truncated packet is left behind.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        directory = os.path.dirname(os.path.abspath(path)) or "."
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except BaseException:
        # The exclusive create above succeeded, so this path is ours;
        # remove it rather than leave a partial packet behind.
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def _required_export_options(args: argparse.Namespace) -> list[str]:
    return [
        name
        for name in ("max_bytes", "session", "keyring", "issuer",
                     "key_version", "moment")
        if getattr(args, name) is None
    ]


def _run_replication_export(args: argparse.Namespace) -> int:
    missing = _required_export_options(args)
    if missing:
        return _fail(
            "replication export requires "
            + ", ".join(f"--{name.replace('_', '-')}" for name in missing)
        )
    audit_path, output_path = args.paths

    # Refuse an existing destination before generating anything; the
    # exclusive create below makes the guarantee race-free as well.
    try:
        if os.path.exists(output_path):
            return _fail(f"output file already exists: {output_path}")
        keyring = _read_json_utf8(args.keyring)
        packet = replication.export_signed_batch(
            audit_path,
            args.after,
            args.max_bytes,
            args.session,
            keyring,
            args.issuer,
            args.key_version,
            args.moment,
        )
        _write_new_durable(output_path, packet)
    except (OSError, UnicodeDecodeError, TypeError, ValueError) as exc:
        return _fail(exc)

    _emit_line(
        {
            "status": "exported",
            "output": output_path,
            "bytes": len(packet),
            "digest": hashlib.sha256(packet).hexdigest(),
        }
    )
    return 0


def _run_replication_import(args: argparse.Namespace) -> int:
    if args.keyring is None:
        return _fail("replication import requires --keyring")
    if args.moment is None:
        return _fail("replication import requires --moment")
    audit_path, package_path = args.paths

    try:
        with open(package_path, "rb") as handle:
            packet = handle.read()
        max_bytes = args.max_bytes
        if max_bytes is None:
            max_bytes = _IMPORT_DEFAULT_MAX_BYTES
        # Reject an over-budget packet before parsing, key lookup or any
        # contact with the target audit, matching import_signed_batch's
        # own admission ordering (exactly at the limit is accepted).
        if len(packet) > max_bytes:
            return _fail("signed batch exceeds max_bytes")
        keyring = _read_json_utf8(args.keyring)
        result = replication.import_signed_batch(
            audit_path, packet, keyring, args.moment, max_bytes
        )
    except (OSError, UnicodeDecodeError, TypeError, ValueError) as exc:
        return _fail(exc)

    _emit_line(result)
    return 1 if result["status"] in ("missing", "fork") else 0


def _run_replication(args: argparse.Namespace) -> int:
    if args.action == "export":
        return _run_replication_export(args)
    return _run_replication_import(args)


def main() -> int:
    parser = argparse.ArgumentParser(prog="offline-coordination")
    subparsers = parser.add_subparsers(dest="command", required=True)
    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--ledger", nargs="+")
    status_parser.add_argument("--max-bytes", type=int)
    recovery = subparsers.add_parser("recovery")
    recovery.add_argument("action", choices=["check", "run", "audit"])
    recovery.add_argument("paths", nargs="+")
    recovery.add_argument("--keyring")
    recovery.add_argument("--ticket")
    recovery.add_argument("--moment", type=int)
    recovery.add_argument("--audit")
    recovery.add_argument("--after", type=int, default=0)
    recovery.add_argument("--limit", type=int, default=100)
    replication_parser = subparsers.add_parser("replication")
    replication_parser.add_argument("action", choices=["export", "import"])
    replication_parser.add_argument("paths", nargs=2)
    replication_parser.add_argument("--after", type=int, default=0)
    replication_parser.add_argument("--max-bytes", type=int, dest="max_bytes")
    replication_parser.add_argument("--session")
    replication_parser.add_argument("--keyring")
    replication_parser.add_argument("--issuer")
    replication_parser.add_argument("--key-version", type=int,
                                    dest="key_version")
    replication_parser.add_argument("--moment", type=int)
    args = parser.parse_args()
    if args.command == "status":
        if args.ledger is None:
            if args.max_bytes is not None:
                print(
                    "--max-bytes requires --ledger LEDGER [LEDGER ...]",
                    file=sys.stderr,
                )
                return 2
            print(json.dumps(status(), sort_keys=True))
            return 0
        try:
            report = replication.inspect_node(
                args.ledger,
                args.max_bytes
                if args.max_bytes is not None
                else replication.DEFAULT_INSPECT_MAX_BYTES,
            )
        except (TypeError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        _emit_line(report)
        return 0 if report["health"] == "healthy" else 1
    if args.command == "replication":
        return _run_replication(args)
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
