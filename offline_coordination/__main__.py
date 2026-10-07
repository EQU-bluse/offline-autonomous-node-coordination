from __future__ import annotations

import argparse
import hashlib
import json
import os
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


def _read_json_file(path: str, what: str) -> object:
    """Read a file as UTF-8 JSON, with a definite message on every fault."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
        return json.loads(raw.decode("utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read {what}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ValueError(f"{what} is not valid UTF-8: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{what} is not valid JSON: {exc}") from exc


def _durable_write(path: str, payload: bytes) -> None:
    """Create ``path`` with ``payload`` durally, never overwriting.

    The file is created with ``O_EXCL`` (the kernel rejects an existing
    path atomically), fully written, flushed and fsynced before the
    directory is fsynced.  Any failure after creation removes the file,
    so a failed command leaves no partial packet behind.
    """
    directory = os.path.dirname(os.path.abspath(path))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    created = False
    fd = os.open(path, flags, 0o666)
    created = True
    try:
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        created = True
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except BaseException:
        if created:
            # Publication was not acknowledged: roll the new file back.
            try:
                os.unlink(path)
            except OSError:
                pass
        raise


def _run_replication_export(args: argparse.Namespace) -> int:
    if os.path.exists(args.output):
        print(f"output file already exists: {args.output}", file=sys.stderr)
        return 2
    try:
        keyring = _read_json_file(args.keyring, "keyring")
        packet = replication.export_signed_batch(
            args.audit,
            args.after,
            args.max_bytes,
            args.session,
            keyring,
            args.issuer,
            args.key_version,
            args.moment,
        )
        _durable_write(args.output, packet)
    except (TypeError, ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    _emit_line(
        {
            "status": "exported",
            "output": args.output,
            "bytes": len(packet),
            "digest": hashlib.sha256(packet).hexdigest(),
        }
    )
    return 0


# Mirrors the receiver-side default of replication.import_signed_batch.
DEFAULT_IMPORT_MAX_BYTES = 67108864


def _run_replication_import(args: argparse.Namespace) -> int:
    max_bytes = (
        args.max_bytes
        if args.max_bytes is not None
        else DEFAULT_IMPORT_MAX_BYTES
    )
    try:
        with open(args.package, "rb") as handle:
            packet = handle.read()
        # The length gate is enforced before parsing, key lookup or any
        # contact with the target audit, exactly as the protocol states.
        if len(packet) > max_bytes:
            raise ValueError("signed batch exceeds max_bytes")
        keyring = _read_json_file(args.keyring, "keyring")
        result = replication.import_signed_batch(
            args.audit, packet, keyring, args.moment, max_bytes
        )
    except (TypeError, ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    _emit_line(result)
    return 1 if result["status"] in ("missing", "fork") else 0


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
    export_parser = subparsers.add_parser("replication")
    export_subparsers = export_parser.add_subparsers(dest="replication_command", required=True)
    export_cmd = export_subparsers.add_parser("export")
    export_cmd.add_argument("audit")
    export_cmd.add_argument("output")
    export_cmd.add_argument("--after", type=int, required=True)
    export_cmd.add_argument("--max-bytes", type=int, required=True)
    export_cmd.add_argument("--session", required=True)
    export_cmd.add_argument("--keyring", required=True)
    export_cmd.add_argument("--issuer", required=True)
    export_cmd.add_argument("--key-version", type=int, required=True)
    export_cmd.add_argument("--moment", type=int, required=True)
    import_cmd = export_subparsers.add_parser("import")
    import_cmd.add_argument("audit")
    import_cmd.add_argument("package")
    import_cmd.add_argument("--keyring", required=True)
    import_cmd.add_argument("--moment", type=int, required=True)
    import_cmd.add_argument("--max-bytes", type=int)
    args = parser.parse_args()
    if args.command == "replication":
        if args.replication_command == "export":
            return _run_replication_export(args)
        return _run_replication_import(args)
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
