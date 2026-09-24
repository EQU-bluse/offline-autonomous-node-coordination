# Offline Autonomous Node Coordination

Minimal backend baseline for autonomous nodes that must keep working during long network outages and later reconcile state with explainable rules.

Requires Python 3.11 or newer and has no third-party runtime dependencies.

```bash
python -m offline_coordination status
python -m offline_coordination recovery check LEDGER [LEDGER ...]
python -m offline_coordination recovery run LEDGER [LEDGER ...]
python -m offline_coordination recovery run LEDGER [...] --keyring KEYRING --ticket TICKET --audit AUDIT --moment MOMENT
python -m offline_coordination recovery audit AUDIT [--after N] [--limit N]
python -m unittest discover -s tests -v
```

The baseline exposes a local status command plus offline ledger recovery operations. Persistent state is available via `offline_coordination.storage`, an append-only hash-chained audit log via `offline_coordination.audit`, and the authorized-recovery chain via `offline_coordination.recovery_audit`. Replication, conflict policies, security boundaries, observability, and network services are intentionally left for subsequent tasks.

## Authorized recovery runs

`offline_coordination.replication.recover_authorized(paths, keyring, ticket, audit_path, moment)` runs an ordered recovery batch only after offline authorization, recording every step in an immutable hash-chained audit; it is the library entry point with the same semantics as the authorized `recovery run`. `recovery check` and the unsigned `recovery run` are unchanged, and the authorized form is selected by giving `--keyring`, `--ticket`, `--audit` and `--moment` together (the first three are file paths).

- **Keyring.** Reuses the signed-replication keyring: a dict mapping issuer (node) names to credential entries, each with exactly `version` (positive, unique per issuer), `secret` (64 lowercase hex characters decoding to the 32-byte HMAC key), `notBefore`/`notAfter` (a closed inclusive validity window of non-negative integers) and `revoked`. Keys are selected by exact issuer and key version with no fallback.
- **Ticket.** Raw bytes containing one canonical compact UTF-8 JSON object with exactly `payload` and `signature`. The payload contains exactly `issuer`, `keyVersion`, `nonce` (16–64 URL-safe characters), `notBefore`/`notAfter` and the ordered `paths`. The signature is the lowercase hex HMAC-SHA256 over the payload's own compact JSON bytes (keys recursively sorted, non-ASCII preserved). The command paths must equal the ticket paths element-for-element — no added, dropped, reordered or implicitly normalized entry.
- **Failures.** Unknown issuer/version, revoked, not-yet-valid or expired key, a ticket outside its own window, a path mismatch and a wrong signature raise `AuthenticationError`; type faults in the arguments, bytes, paths or moment (a `bool` never poses as a moment) raise `TypeError`; bad ticket key sets, nonce, intervals, encoding or signature format raise `ValueError`. All verification completes before any ledger or audit file is read, so a rejected call creates no audit record, consumes no nonce and leaves no temporary file. The same nonce later bound to a different ticket raises `ReplayError` (a `ValueError`) without touching a file.
- **Audit.** `offline_coordination.recovery_audit` is a version-1 canonical JSONL hash chain of `batch`, `before` and `after` records. First use of a nonce persists the batch header — ticket digest (SHA-256 of the canonical payload bytes), issuer and ordered paths — before any ledger is read. Each ledger then records a `before` line (current digest, recovery phase, predetermined action), is settled in `recover_many` order, and records an `after` line (new digest, status, failure category); every line is written, flushed and fsynced before work continues. Results keep the public `recover_many` item shape (`path`, `status`, `digest`, `error`) and blocked/system failures stay isolated per ledger. Re-entering with the same nonce and ticket reuses recorded results and only settles the open tail; a crash after recovery but before the result is recorded is completed from the recorded action and digest without repeating the side effect. A corrupt chain raises `CorruptRecoveryAuditError` (a `ValueError`); audit read/write/flush/sync failures propagate as `OSError`, leaving a retryable consistent prefix.
- **Export.** `recovery_audit.export_page(path, after, limit)` (the `recovery audit` command) is read-only: a non-negative cursor, a limit of 1–1000, the page `{"after","complete","next","records","version":1}`, full chain validation, and a missing audit treated as an empty chain.

The authorized command prints exactly one compact, recursively key-sorted JSON line of `recover_many` items, exits 0 on success, 1 when a ledger is blocked/failed or the audit chain/filesystem fails, and 2 on authorization, replay or parameter errors.


## Ledger recovery

`offline_coordination.replication.recover_ledger(path)` settles one interrupted ledger transaction. Its `clean` result (no recovery intent) reports the SHA-256 of the current ledger bytes, lowercase hex, or `None` when the path is missing.

Two batch entry points operate on an explicit, non-empty list of distinct, non-empty ledger paths, validated in full before any file is read or modified (`TypeError` for container/element type faults, `ValueError` for an empty list, empty path or duplicate):

- `inspect_recovery(paths)` — read-only diagnostics. Each report carries `path`, `status`, `phase`, `digest`, `artifacts`, `action` and `error`: `clean` when no intent exists, `pending` with the suggested action (`rollback`/`complete`) and candidate/predecessor existence, digest-match and completeness when an intent is valid, `blocked`/`corrupt` when the intent or a necessary artifact is invalid, and `failed`/`os-error` when reading fails. Nothing is created, modified or deleted, and random artifacts are never scanned.
- `recover_many(paths)` — controlled batch recovery. Each ledger is recovered via `recover_ledger` in order; one failure never stops or rolls back the others. Successful items keep the `clean`/`rolled-back`/`completed` statuses; a `CorruptRecoveryError` becomes a `blocked`/`corrupt` item and an `OSError` a `failed`/`os-error` item, leaving enough intent and artifacts behind for an independent retry.

The module entry points `recovery check` and `recovery run` wrap these: they print exactly one line of compact UTF-8 JSON with recursively sorted keys, exit 0 when every ledger succeeds, 1 when any ledger is blocked or failed, and 2 on syntax or argument errors.
