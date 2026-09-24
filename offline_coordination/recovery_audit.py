"""Immutable, hash-chained audit log for authorized recovery runs.

The recovery audit is a version-1 canonical UTF-8 JSONL file, one JSON
object per line, distinct from the generic :mod:`offline_coordination.audit`
event log.  Each object has the fixed key set (and key order)::

    detail, hash, kind, prev, seq

``seq`` starts at 1 and is contiguous; the first record's ``prev`` is 64
zero characters and every later ``prev`` equals the previous record's
``hash``.  ``hash`` is the lowercase hex SHA-256 of the compact UTF-8 JSON
encoding (no whitespace, non-ASCII preserved, no trailing newline) of the
record with the ``hash`` key itself removed.  Each complete record line is
encoded the same way and terminated by exactly one ``\\n``.

Three record kinds mark an authorized run:

- ``batch``: the first record of a run, persisted before any ledger is
  touched, carrying the authorizing ``issuer``, the ticket ``nonce``, the
  exact ordered ``paths`` and ``ticketDigest`` (the lowercase hex SHA-256
  of the ticket's canonical payload bytes).
- ``before``: written immediately before one ledger is settled, carrying
  its ``path``, the recovery ``phase`` (``prepared``/``installed``/null),
  the predetermined ``action`` (``rollback``/``complete``/null) and the
  ``digest`` observed beforehand (null when the path is missing or could
  not be read).
- ``after``: written immediately after that ledger settles, carrying the
  same ``path``, the resulting ``digest`` (null for blocked/failed items),
  the ``status`` (``clean``/``rolled-back``/``completed``/``blocked``/
  ``failed``) and the failure ``error`` (null/``corrupt``/``os-error``).

Every ``before`` record is paired with exactly one immediately following
``after`` record, so a crash between them leaves a recognizable open
item that a re-entry completes from the recorded plan instead of
re-executing the side effect.  A missing log stands for an empty chain;
an existing log that violates any byte, structure, domain, ordering or
hash rule is corrupt.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any

DETAIL = "detail"
HASH = "hash"
KIND = "kind"
PREV = "prev"
SEQ = "seq"

ISSUER = "issuer"
NONCE = "nonce"
PATHS = "paths"
TICKET_DIGEST = "ticketDigest"

ACTION = "action"
DIGEST = "digest"
ERROR = "error"
PATH = "path"
PHASE = "phase"
STATUS = "status"

KIND_BATCH = "batch"
KIND_BEFORE = "before"
KIND_AFTER = "after"

ACTION_ROLLBACK = "rollback"
ACTION_COMPLETE = "complete"

PHASE_PREPARED = "prepared"
PHASE_INSTALLED = "installed"

STATUS_CLEAN = "clean"
STATUS_ROLLED_BACK = "rolled-back"
STATUS_COMPLETED = "completed"
STATUS_BLOCKED = "blocked"
STATUS_FAILED = "failed"

ERROR_CORRUPT = "corrupt"
ERROR_OS_ERROR = "os-error"

ZERO_HASH = "0" * 64

_AFTER = "after"
_COMPLETE = "complete"
_NEXT = "next"
_RECORDS = "records"
_VERSION = "version"
_PAGE_VERSION = 1
_MIN_LIMIT = 1
_MAX_LIMIT = 1000

_RECORD_KEYS = (DETAIL, HASH, KIND, PREV, SEQ)
_HASHED_KEYS = (DETAIL, KIND, PREV, SEQ)
_PAGE_KEYS = (_AFTER, _COMPLETE, _NEXT, _RECORDS, _VERSION)
_BATCH_DETAIL_KEYS = frozenset((ISSUER, NONCE, PATHS, TICKET_DIGEST))
_BEFORE_DETAIL_KEYS = frozenset((ACTION, DIGEST, PATH, PHASE))
_AFTER_DETAIL_KEYS = frozenset((DIGEST, ERROR, PATH, STATUS))
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
NONCE_RE = re.compile(r"[A-Za-z0-9_-]{16,64}\Z")

_ITEM_STATUSES = frozenset((
    STATUS_CLEAN,
    STATUS_ROLLED_BACK,
    STATUS_COMPLETED,
    STATUS_BLOCKED,
    STATUS_FAILED,
))
_FAILURE_BY_STATUS = {
    STATUS_BLOCKED: ERROR_CORRUPT,
    STATUS_FAILED: ERROR_OS_ERROR,
}
_PLAN_BY_PHASE = {
    PHASE_PREPARED: ACTION_ROLLBACK,
    PHASE_INSTALLED: ACTION_COMPLETE,
}


class CorruptRecoveryAuditError(ValueError):
    """The recovery audit file exists but is not a valid recovery chain."""


def _audit_invalid(message: str) -> CorruptRecoveryAuditError:
    return CorruptRecoveryAuditError(f"invalid recovery audit: {message}")


def _compact(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple]) -> dict:
    """``object_pairs_hook`` turning duplicate object keys into corruption."""
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise _audit_invalid(f"duplicate key {key!r} in record")
        result[key] = value
    return result


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST_RE.fullmatch(value) is not None


def _validate_detail(kind: str, detail: object, where: str) -> dict:
    """Validate one record detail against its kind's value domain."""
    if not isinstance(detail, dict):
        raise _audit_invalid(f"{where} detail must be a JSON object")

    if kind == KIND_BATCH:
        if set(detail.keys()) != _BATCH_DETAIL_KEYS:
            raise _audit_invalid(
                f"{where} batch detail must contain exactly the keys "
                "'issuer', 'nonce', 'paths' and 'ticketDigest'"
            )
        issuer = detail[ISSUER]
        nonce = detail[NONCE]
        paths = detail[PATHS]
        ticket_digest = detail[TICKET_DIGEST]
        if not isinstance(issuer, str) or issuer == "":
            raise _audit_invalid(f"{where} issuer must be a non-empty str")
        if not isinstance(nonce, str) or NONCE_RE.fullmatch(nonce) is None:
            raise _audit_invalid(
                f"{where} nonce must be 16 to 64 URL-safe characters"
            )
        if not isinstance(paths, list) or not paths:
            raise _audit_invalid(
                f"{where} paths must be a non-empty array"
            )
        seen: set[str] = set()
        for position, path in enumerate(paths):
            if not isinstance(path, str) or path == "":
                raise _audit_invalid(
                    f"{where} paths entry {position} must be a non-empty str"
                )
            if path in seen:
                raise _audit_invalid(
                    f"{where} paths entry {path!r} is repeated"
                )
            seen.add(path)
        if not _is_digest(ticket_digest):
            raise _audit_invalid(
                f"{where} ticketDigest must be 64 lowercase hex characters"
            )
        return {
            ISSUER: issuer,
            NONCE: nonce,
            PATHS: list(paths),
            TICKET_DIGEST: ticket_digest,
        }

    if kind == KIND_BEFORE:
        if set(detail.keys()) != _BEFORE_DETAIL_KEYS:
            raise _audit_invalid(
                f"{where} before detail must contain exactly the keys "
                "'action', 'digest', 'path' and 'phase'"
            )
        path = detail[PATH]
        phase = detail[PHASE]
        action = detail[ACTION]
        digest = detail[DIGEST]
        if not isinstance(path, str) or path == "":
            raise _audit_invalid(f"{where} path must be a non-empty str")
        if phase is not None and phase not in _PLAN_BY_PHASE:
            raise _audit_invalid(
                f"{where} phase must be null, 'prepared' or 'installed'"
            )
        expected_action = _PLAN_BY_PHASE.get(phase)
        if action != expected_action:
            raise _audit_invalid(
                f"{where} action {action!r} does not match phase {phase!r}"
            )
        if digest is not None and not _is_digest(digest):
            raise _audit_invalid(
                f"{where} digest must be null or 64 lowercase hex characters"
            )
        return {
            ACTION: action,
            DIGEST: digest,
            PATH: path,
            PHASE: phase,
        }

    # kind == KIND_AFTER
    if set(detail.keys()) != _AFTER_DETAIL_KEYS:
        raise _audit_invalid(
            f"{where} after detail must contain exactly the keys 'digest', "
            "'error', 'path' and 'status'"
        )
    path = detail[PATH]
    status = detail[STATUS]
    error = detail[ERROR]
    digest = detail[DIGEST]
    if not isinstance(path, str) or path == "":
        raise _audit_invalid(f"{where} path must be a non-empty str")
    if not isinstance(status, str) or status not in _ITEM_STATUSES:
        raise _audit_invalid(f"{where} status is not a known recovery status")
    expected_error = _FAILURE_BY_STATUS.get(status)
    if (error is None) != (expected_error is None):
        raise _audit_invalid(
            f"{where} error {error!r} does not match status {status!r}"
        )
    if expected_error is not None and error != expected_error:
        raise _audit_invalid(
            f"{where} error {error!r} does not match status {status!r}"
        )
    # A null digest is legitimate not only for blocked/failed items but
    # also for a clean or rolled-back ledger whose path is (again)
    # missing, so only the digest's shape is constrained.
    if digest is not None and not _is_digest(digest):
        raise _audit_invalid(
            f"{where} digest must be null or 64 lowercase hex characters"
        )
    return {
        DIGEST: digest,
        ERROR: error,
        PATH: path,
        STATUS: status,
    }


def _record_hash(without_hash: dict[str, Any]) -> str:
    ordered = {key: without_hash[key] for key in _HASHED_KEYS}
    return hashlib.sha256(_compact(ordered)).hexdigest()


def _encode_line(record: dict[str, Any]) -> bytes:
    ordered = {key: record[key] for key in _RECORD_KEYS}
    return _compact(ordered) + b"\n"


def _parse_chain(raw: bytes) -> list[dict[str, Any]]:
    """Validate every byte of a recovery audit chain and return records."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _audit_invalid("file is not valid UTF-8") from exc

    records: list[dict[str, Any]] = []
    expected_seq = 1
    expected_prev = ZERO_HASH
    run_paths: list[str] = []
    pair_count = 0
    open_before: dict[str, Any] | None = None

    if text == "":
        return records
    lines = text.split("\n")
    if lines[-1] != "":
        raise _audit_invalid("the last line is not terminated by a newline")
    for line_no, line in enumerate(lines[:-1], start=1):
        where = f"line {line_no}"
        try:
            data = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
        except json.JSONDecodeError as exc:
            raise _audit_invalid(f"{where} is not valid JSON") from exc
        if not isinstance(data, dict) or set(data.keys()) != set(_RECORD_KEYS):
            raise _audit_invalid(
                f"{where} must contain exactly the keys detail, hash, kind, "
                "prev, seq"
            )
        kind = data[KIND]
        if kind not in (KIND_BATCH, KIND_BEFORE, KIND_AFTER):
            raise _audit_invalid(
                f"{where} kind must be 'batch', 'before' or 'after'"
            )
        seq = data[SEQ]
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise _audit_invalid(f"{where} seq must be an int")
        if seq != expected_seq:
            raise _audit_invalid(
                f"{where} seq is {seq}, expected {expected_seq}"
            )
        prev = data[PREV]
        if prev != expected_prev:
            raise _audit_invalid(f"{where} prev does not match the previous hash")

        if kind == KIND_BATCH:
            if records and (
                open_before is not None or pair_count != len(run_paths)
            ):
                raise _audit_invalid(
                    f"{where} a new batch cannot interrupt an unfinished run"
                )
        elif kind == KIND_BEFORE:
            if not records or records[-1][KIND] == KIND_BEFORE:
                raise _audit_invalid(
                    f"{where} before record is missing its batch or is not "
                    "paired with an after record"
                )
        else:
            if open_before is None:
                raise _audit_invalid(
                    f"{where} after record has no immediately preceding before"
                )

        detail = _validate_detail(kind, data[DETAIL], where)

        if kind == KIND_BATCH:
            run_paths = detail[PATHS]
            pair_count = 0
            open_before = None
        elif kind == KIND_BEFORE:
            if pair_count >= len(run_paths):
                raise _audit_invalid(
                    f"{where} before record has no matching batch path"
                )
            expected_path = run_paths[pair_count]
            if detail[PATH] != expected_path:
                raise _audit_invalid(
                    f"{where} before path {detail[PATH]!r} does not follow the "
                    f"batch path order ({expected_path!r} expected)"
                )
            open_before = detail
        else:
            assert open_before is not None
            if detail[PATH] != open_before[PATH]:
                raise _audit_invalid(
                    f"{where} after path {detail[PATH]!r} does not match its "
                    f"before path {open_before[PATH]!r}"
                )
            open_before = None
            pair_count += 1

        digest = data[HASH]
        if not _is_digest(digest):
            raise _audit_invalid(f"{where} hash must be 64 lowercase hex chars")
        without_hash = {
            DETAIL: detail,
            KIND: kind,
            PREV: prev,
            SEQ: seq,
        }
        if _record_hash(without_hash) != digest:
            raise _audit_invalid(f"{where} hash does not match its contents")
        record = dict(without_hash)
        record[HASH] = digest
        if _compact({key: record[key] for key in _RECORD_KEYS}) != line.encode("utf-8"):
            raise _audit_invalid(f"{where} is not canonically encoded")
        records.append(record)
        expected_seq += 1
        expected_prev = digest

    return records


def read_chain(path: str) -> list[dict[str, Any]]:
    """Return all recovery audit records as a fresh validated list.

    A missing or empty file yields an empty list.  A corrupt chain raises
    :class:`CorruptRecoveryAuditError`; other filesystem errors propagate
    as :class:`OSError`.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return []
    return _parse_chain(raw)


def append_record(path: str, kind: str, detail: dict[str, Any]) -> int:
    """Validate the whole chain and append one record, returning its seq.

    The existing chain is fully verified before anything is written, so a
    corrupt audit is never extended.  Ordering rules additionally require a
    ``batch`` record at the head, a ``before`` record only when no item is
    open and an ``after`` record only right after its ``before``.  The new
    line is written, flushed and fsynced before the call returns; when the
    file is newly created its parent directory is fsynced as well.
    Filesystem failures propagate unchanged as :class:`OSError`.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    records = read_chain(path)
    validated_detail = _validate_detail(kind, detail, "new record")
    # Enforce the same run state machine the parser enforces, so a
    # transition that would corrupt the chain is never written: an empty
    # chain accepts only a batch; a new batch may follow solely at the
    # head or after a run whose every declared path is closed; a before
    # may follow a batch or a closed item; an after must close the open
    # before and may not name a different path.
    last_batch = -1
    for index in range(len(records) - 1, -1, -1):
        if records[index][KIND] == KIND_BATCH:
            last_batch = index
            break
    run_records = records[last_batch + 1:] if last_batch >= 0 else []
    closed_pairs = sum(1 for record in run_records if record[KIND] == KIND_AFTER)
    open_before = (
        run_records[-1][DETAIL]
        if run_records and run_records[-1][KIND] == KIND_BEFORE
        else None
    )
    last_kind = records[-1][KIND] if records else None

    if kind == KIND_BATCH:
        if last_batch >= 0:
            run_paths = records[last_batch][DETAIL][PATHS]
            if open_before is not None or closed_pairs != len(run_paths):
                raise _audit_invalid(
                    "a batch record cannot interrupt an unfinished run"
                )
    elif kind == KIND_BEFORE:
        if last_kind not in (KIND_BATCH, KIND_AFTER):
            raise _audit_invalid(
                "a before record requires a batch or a completed item first"
            )
        if last_batch < 0:
            raise _audit_invalid("a before record requires a preceding batch")
        run_paths = records[last_batch][DETAIL][PATHS]
        if closed_pairs >= len(run_paths):
            raise _audit_invalid("a before record has no matching batch path")
        expected_path = run_paths[closed_pairs]
        if validated_detail[PATH] != expected_path:
            raise _audit_invalid(
                "a before record does not follow the batch path order"
            )
    else:
        if open_before is None:
            raise _audit_invalid(
                "an after record must immediately follow its before record"
            )
        if validated_detail[PATH] != open_before[PATH]:
            raise _audit_invalid(
                "an after record path must match its before record path"
            )

    existed = os.path.exists(path)
    seq = len(records) + 1
    prev = records[-1][HASH] if records else ZERO_HASH
    without_hash = {
        DETAIL: validated_detail,
        KIND: kind,
        PREV: prev,
        SEQ: seq,
    }
    record = dict(without_hash)
    record[HASH] = _record_hash(without_hash)

    with open(path, "ab") as handle:
        handle.write(_encode_line(record))
        handle.flush()
        os.fsync(handle.fileno())

    if not existed:
        fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return seq


def export_page(path: str, after: int = 0, limit: int = 100) -> bytes:
    """Export one read-only page of recovery audit records as JSON bytes.

    Selects the first ``limit`` records whose ``seq`` is greater than
    ``after``.  ``after`` must be a non-negative non-bool int and not
    exceed the chain's last seq (a missing audit file is an empty chain,
    whose last seq is 0); ``limit`` must be a non-bool int in
    ``[1, 1000]``.  The page is one compact UTF-8 JSON object with the
    fixed top-level key order ``after``, ``complete``, ``next``,
    ``records`` and ``version`` (the integer 1); records preserve the
    recovery-audit record key order ``detail``, ``hash``, ``kind``,
    ``prev`` and ``seq`` and their original values.  ``next`` is the seq
    of the last record in the page, or ``after`` when the page is empty;
    ``complete`` is true when nothing follows the page, and an empty
    records list is only valid at the tail of an empty chain.  The audit
    is never modified: a corrupt chain raises
    :class:`CorruptRecoveryAuditError` and filesystem faults propagate as
    :class:`OSError`.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    if isinstance(after, bool) or not isinstance(after, int):
        raise TypeError("after must be an int")
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise TypeError("limit must be an int")
    if after < 0:
        raise ValueError("after must be >= 0")
    if limit < _MIN_LIMIT or limit > _MAX_LIMIT:
        raise ValueError("limit must be in [1, 1000]")

    all_records = read_chain(path)
    last_seq = all_records[-1][SEQ] if all_records else 0
    if after > last_seq:
        raise ValueError("after must not exceed the last recovery audit seq")

    selected = [
        record for record in all_records if record[SEQ] > after
    ][:limit]
    page_records = [
        {key: record[key] for key in _RECORD_KEYS} for record in selected
    ]
    next_seq = page_records[-1][SEQ] if page_records else after
    page = {
        _AFTER: after,
        _COMPLETE: next_seq == last_seq,
        _NEXT: next_seq,
        _RECORDS: page_records,
        _VERSION: _PAGE_VERSION,
    }
    ordered = {key: page[key] for key in _PAGE_KEYS}
    text = json.dumps(ordered, ensure_ascii=False, separators=(",", ":")) + "\n"
    return text.encode("utf-8")
