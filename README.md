# Offline Autonomous Node Coordination

Minimal backend baseline for autonomous nodes that must keep working during long network outages and later reconcile state with explainable rules.

Requires Python 3.11 or newer and has no third-party runtime dependencies.

```bash
python -m offline_coordination status
python -m offline_coordination recovery check LEDGER [LEDGER ...]
python -m offline_coordination recovery run LEDGER [LEDGER ...]
python -m unittest discover -s tests -v
```

The baseline exposes a local status command plus offline ledger recovery operations. Persistent state is available via `offline_coordination.storage` and an append-only hash-chained audit log via `offline_coordination.audit`. Replication, conflict policies, security boundaries, observability, and network services are intentionally left for subsequent tasks.

## Ledger recovery

`offline_coordination.replication.recover_ledger(path)` settles one interrupted ledger transaction. Its `clean` result (no recovery intent) reports the SHA-256 of the current ledger bytes, lowercase hex, or `None` when the path is missing.

Two batch entry points operate on an explicit, non-empty list of distinct, non-empty ledger paths, validated in full before any file is read or modified (`TypeError` for container/element type faults, `ValueError` for an empty list, empty path or duplicate):

- `inspect_recovery(paths)` — read-only diagnostics. Each report carries `path`, `status`, `phase`, `digest`, `artifacts`, `action` and `error`: `clean` when no intent exists, `pending` with the suggested action (`rollback`/`complete`) and candidate/predecessor existence, digest-match and completeness when an intent is valid, `blocked`/`corrupt` when the intent or a necessary artifact is invalid, and `failed`/`os-error` when reading fails. Nothing is created, modified or deleted, and random artifacts are never scanned.
- `recover_many(paths)` — controlled batch recovery. Each ledger is recovered via `recover_ledger` in order; one failure never stops or rolls back the others. Successful items keep the `clean`/`rolled-back`/`completed` statuses; a `CorruptRecoveryError` becomes a `blocked`/`corrupt` item and an `OSError` a `failed`/`os-error` item, leaving enough intent and artifacts behind for an independent retry.

The module entry points `recovery check` and `recovery run` wrap these: they print exactly one line of compact UTF-8 JSON with recursively sorted keys, exit 0 when every ledger succeeds, 1 when any ledger is blocked or failed, and 2 on syntax or argument errors.
