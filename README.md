# Offline Autonomous Node Coordination

Minimal backend baseline for autonomous nodes that must keep working during long network outages and later reconcile state with explainable rules.

Requires Python 3.11 or newer and has no third-party runtime dependencies.

```bash
python -m offline_coordination status
python -m offline_coordination recovery check LEDGER [LEDGER ...]
python -m offline_coordination recovery run LEDGER [LEDGER ...] --keyring KEYRING --ticket TICKET --moment MOMENT --audit AUDIT
python -m offline_coordination recovery audit AUDIT [--after N] [--limit N]
python -m unittest discover -s tests -v
```

The baseline exposes a local status command plus offline ledger recovery operations. Persistent state is available via `offline_coordination.storage` and an append-only hash-chained audit log via `offline_coordination.audit`. Replication, conflict policies, security boundaries, observability, and network services are intentionally left for subsequent tasks.

## Ledger recovery

`offline_coordination.replication.recover_ledger(path)` settles one interrupted ledger transaction. Its `clean` result (no recovery intent) reports the SHA-256 of the current ledger bytes, lowercase hex, or `None` when the path is missing.

Two batch entry points operate on an explicit, non-empty list of distinct, non-empty ledger paths, validated in full before any file is read or modified (`TypeError` for container/element type faults, `ValueError` for an empty list, empty path or duplicate):

- `inspect_recovery(paths)` — read-only diagnostics. Each report carries `path`, `status`, `phase`, `digest`, `artifacts`, `action` and `error`: `clean` when no intent exists, `pending` with the suggested action (`rollback`/`complete`) and candidate/predecessor existence, digest-match and completeness when an intent is valid, `blocked`/`corrupt` when the intent or a necessary artifact is invalid, and `failed`/`os-error` when reading fails. Nothing is created, modified or deleted, and random artifacts are never scanned.
- `recover_many(paths)` — controlled batch recovery. Each ledger is recovered via `recover_ledger` in order; one failure never stops or rolls back the others. Successful items keep the `clean`/`rolled-back`/`completed` statuses; a `CorruptRecoveryError` becomes a `blocked`/`corrupt` item and an `OSError` a `failed`/`os-error` item, leaving enough intent and artifacts behind for an independent retry.

The module entry points `recovery check` and `recovery run` wrap these: they print exactly one line of compact UTF-8 JSON with recursively sorted keys, exit 0 when every ledger succeeds, 1 when any ledger is blocked or failed, and 2 on syntax or argument errors.

## Authorized recovery and the recovery audit

`offline_coordination.replication.recover_authorized(paths, keyring, ticket, moment, audit)` adds an authorization boundary and a durable operation audit around the same batch recovery. The ticket is one canonical compact JSON object with exactly `payload` and `signature`; the payload carries exactly `issuer`, `keyVersion`, `nonce`, `notBefore`, `notAfter` and the ordered `paths`, and the signature is the lowercase hex HMAC-SHA256 of the canonical payload encoding, verified against the keyring (the same version/secret/validity/revocation rules as `apply_signed_remote`, keys selected by exact issuer and version). The command paths must equal the ticket paths item for item — never expanded, reordered or normalized. Unknown credentials, a revoked, not-yet-valid or expired key or ticket, a path mismatch and a signature mismatch all raise `AuthenticationError` before any ledger is read, so a failed authorization creates no audit record, consumes no nonce and leaves no temporary file. Type faults raise `TypeError` (a `bool` never poses as `moment`); a malformed ticket key set, nonce, validity interval, encoding or signature format raises `ValueError`.

Once authorized, the batch runs in the `recover_many` order with the same per-ledger isolation and the same public item structure, and every step is recorded at the audit path as an append-only canonical JSONL hash chain, each record written, flushed and synced before the step it gates: a `batch` header on the first use of a nonce (binding the ticket digest, issuer and ordered paths), then a `before` record (original digest, phase, planned action) and an `after` record (new digest, status, failure category) per ledger. An `OSError` while reading the audit or writing, flushing or syncing a record propagates unchanged and leaves a consistent, retryable chain prefix. Re-entering with the same nonce and the same ticket reuses the recorded results and only continues the paths not yet settled — a process interrupted after a recovery but before its result record is completed from the recorded action and digests, without repeating side effects. The same nonce bound to a different ticket raises `ReplayError` (a `ValueError`) without modifying any file; a corrupt chain raises `CorruptRecoveryAuditError` (a `ValueError`).

`export_recovery_audit(path, after=0, limit=100)` pages the chain read-only (`after`/`complete`/`next`/`records`), validating the whole chain and treating a missing audit as an empty chain. The module entry point `recovery run` requires the four explicit materials `--keyring`, `--ticket`, `--moment` and `--audit` and exits 0 on success, 1 on ledger failures and 2 on authorization or argument errors; `recovery audit AUDIT [--after N] [--limit N]` prints one page of the chain.

## Signed recovery checkpoints and offline page verification

`offline_coordination.replication.export_recovery_checkpoint(path, keyring, issuer, version, moment)` anchors the whole recovery audit chain with a signature, so a wholesale replacement of the history with a recomputed chain is detected offline. It validates the chain read-only and returns the checkpoint bytes: one canonical compact UTF-8 JSON object (recursively sorted keys, no trailing newline) with exactly `payload` and `signature`. The payload binds exactly `version` (the integer 1), `issuer`, `keyVersion`, `moment`, `lastSeq` and `lastHash` — a missing audit yields seq zero and the zero hash — and the signature is the lowercase hex HMAC-SHA256 of the payload's canonical bytes, computed with the key the keyring binds to the exact issuer and version (no fallback). Unusable credentials raise `AuthenticationError`; a corrupt chain raises `CorruptRecoveryAuditError`; an `OSError` while reading propagates unchanged.

`offline_coordination.replication.verify_recovery_page(checkpoint, page, keyring, moment, cursor=None)` verifies one page dict (as produced by `export_recovery_audit`) against a checkpoint without reading any file. The first page must start at `after` zero; each later page continues at the cursor's `next`, and the cursor must bind the same checkpoint digest. Every page's seqs, hash chain and pagination boundaries must be contiguous and self-consistent and never cross the signed last seq — before it is reached, an empty page, gap, reorder, duplicate or `prev` mismatch is rejected. The result carries `checkpointDigest`, `next`, `tail` and `status` (`verified` once the signed chain tail is reached, `continue` before) and doubles as the cursor for the next page. An empty checkpoint only accepts an empty page from zero and reports seq zero, the zero hash and `verified` directly. Type faults raise `TypeError` (a `bool` never poses as an int); a malformed checkpoint raises `InvalidRecoveryCheckpointError`, a malformed page or cursor raises `InvalidRecoveryPageError` (both are `ValueError` subclasses), and unusable credentials or a signature mismatch raise `AuthenticationError`. Neither call modifies its inputs or any file.
